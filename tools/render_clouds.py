# Renders the sky behind the hero.
#
#   "C:/Program Files/Blender Foundation/Blender 4.5/blender.exe" -b -P tools/render_clouds.py
#
# This is an actual 3D sky, not a flat noise texture. A volumetric cloud deck
# sits high above the camera and is photographed from underneath, so the cloud
# recedes toward the horizon and catches the light on its tops while the
# undersides stay dark. That recession and that shading gradient are what make
# a sky read as depth rather than wallpaper. An orthographic slab of noise can
# produce neither, because every column of it is a parallel slice rather than
# a direction you are looking in - which is why the earlier versions looked
# flat no matter how the noise was tuned.
#
# It loops because the camera is EQUIRECTANGULAR across a full 360 degrees of
# longitude. Panning the result horizontally is turning your head; after 360
# degrees you are looking at the same sky again, exactly. Seamless by geometry
# - no cross-fade, no mirrored or repeated imagery.
#
# Three decks at different altitudes give parallax: the CSS drifts them at
# different speeds, so low cloud passes faster than high cloud.

import bpy
import os
import math

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, '..', 'img'))
os.makedirs(OUT, exist_ok=True)

# 360 degrees of longitude by 90 of latitude is 4:1, which keeps pixels square.
W, H = 3600, 900
LAT_MIN, LAT_MAX = -12.0, 78.0

LAYERS = [
    # name,  base,   top,  scale, detail, density, ramp lo,  hi,   sun, samples
    ('near',  30.0,  60.0, 0.0065, 6.0,   7.0,   0.500, 0.610, 1.00, 110),
    ('mid',   58.0,  96.0, 0.0046, 5.0,   5.0,   0.515, 0.625, 0.80,  88),
    ('far',   96.0, 150.0, 0.0032, 4.0,   3.4,   0.530, 0.640, 0.62,  72),
]


def reset():
    bpy.ops.wm.read_factory_settings(use_empty=True)


def setup_render(samples):
    sc = bpy.context.scene
    sc.render.engine = 'CYCLES'
    sc.cycles.device = 'GPU'
    sc.cycles.samples = samples
    sc.cycles.use_denoising = True
    sc.cycles.volume_max_steps = 256
    sc.cycles.volume_step_rate = 0.5
    sc.render.resolution_x = W
    sc.render.resolution_y = H
    sc.render.resolution_percentage = 100
    sc.render.film_transparent = True
    sc.render.image_settings.file_format = 'PNG'
    sc.render.image_settings.color_mode = 'RGBA'
    sc.view_settings.view_transform = 'Standard'

    addon = bpy.context.preferences.addons.get('cycles')
    if addon:
        p = addon.preferences
        for backend in ('OPTIX', 'CUDA'):
            try:
                p.compute_device_type = backend
                p.get_devices()
                if any(d.type == backend for d in p.devices):
                    for d in p.devices:
                        d.use = (d.type == backend)
                    print('cycles backend:', backend)
                    return
            except Exception as e:
                print('backend', backend, 'unavailable:', e)


def build_deck(base, top, scale, detail, density, lo, hi, seed):
    """A wide, flat body of cloud high above the camera."""
    span = 3000.0                       # reaches well past the horizon
    half = (top - base) / 2.0
    bpy.ops.mesh.primitive_cube_add(size=2, location=(0, 0, base + half))
    deck = bpy.context.active_object
    deck.scale = (span, span, half)

    mat = bpy.data.materials.new('cloud')
    mat.use_nodes = True
    nt = mat.node_tree
    for n in list(nt.nodes):
        nt.nodes.remove(n)
    N, L = nt.nodes.new, nt.links.new

    coord = N('ShaderNodeTexCoord')
    geo = N('ShaderNodeNewGeometry')

    # Real world position. Object and Generated coordinates are both normalised
    # to the deck's bounding box, so on a 3000-unit slab they collapse to +-1
    # and the noise comes out constant - which renders as nothing at all.
    mapping = N('ShaderNodeMapping')
    mapping.inputs['Location'].default_value = (seed * 137.0, seed * 91.0, 0.0)
    mapping.inputs['Scale'].default_value = (1.0, 1.0, 3.2)   # wider than tall

    noise = N('ShaderNodeTexNoise')
    noise.inputs['Scale'].default_value = scale
    noise.inputs['Detail'].default_value = detail
    noise.inputs['Roughness'].default_value = 0.52

    ramp = N('ShaderNodeValToRGB')
    ramp.color_ramp.elements[0].position = lo
    ramp.color_ramp.elements[1].position = hi

    # Soft top and bottom, so the deck ends in cloud rather than in the flat
    # faces of the box it lives in.
    sep = N('ShaderNodeSeparateXYZ')
    gz = N('ShaderNodeMath'); gz.operation = 'MULTIPLY'; gz.inputs[1].default_value = 2.0
    gc = N('ShaderNodeMath'); gc.operation = 'SUBTRACT'; gc.inputs[1].default_value = 1.0
    ga = N('ShaderNodeMath'); ga.operation = 'ABSOLUTE'
    gi = N('ShaderNodeMath'); gi.operation = 'SUBTRACT'; gi.inputs[0].default_value = 1.0
    gp = N('ShaderNodeMath'); gp.operation = 'POWER'; gp.inputs[1].default_value = 1.3
    fall = N('ShaderNodeMath'); fall.operation = 'MULTIPLY'

    vol = N('ShaderNodeVolumePrincipled')
    vol.inputs['Color'].default_value = (0.93, 0.95, 1.0, 1.0)
    vol.inputs['Density'].default_value = density
    vol.inputs['Anisotropy'].default_value = 0.45    # bright rims toward the light
    out = N('ShaderNodeOutputMaterial')

    L(geo.outputs['Position'], mapping.inputs['Vector'])
    L(mapping.outputs['Vector'], noise.inputs['Vector'])
    L(noise.outputs['Fac'], ramp.inputs['Fac'])
    L(coord.outputs['Generated'], sep.inputs['Vector'])
    L(sep.outputs['Z'], gz.inputs[0])
    L(gz.outputs[0], gc.inputs[0])
    L(gc.outputs[0], ga.inputs[0])
    L(ga.outputs[0], gi.inputs[1])
    L(gi.outputs[0], gp.inputs[0])
    L(ramp.outputs['Color'], fall.inputs[0])
    L(gp.outputs[0], fall.inputs[1])
    L(fall.outputs[0], vol.inputs['Density'])
    L(vol.outputs['Volume'], out.inputs['Volume'])

    deck.data.materials.append(mat)
    return deck


def build_lights(strength):
    # A low, hard key rakes the deck so tops light and undersides fall away.
    key = bpy.data.lights.new('key', type='SUN')
    key.energy = 16.0 * strength
    key.angle = math.radians(2.0)
    key.color = (1.0, 0.98, 0.95)
    ko = bpy.data.objects.new('key', key)
    ko.rotation_euler = (math.radians(72), 0, math.radians(36))
    bpy.context.collection.objects.link(ko)

    # Cool bounce so the shadowed sides read dark but not dead.
    fill = bpy.data.lights.new('fill', type='SUN')
    fill.energy = 1.8 * strength
    fill.color = (0.60, 0.73, 0.96)
    fo = bpy.data.objects.new('fill', fill)
    fo.rotation_euler = (math.radians(-26), 0, math.radians(-148))
    bpy.context.collection.objects.link(fo)


def build_camera():
    cam = bpy.data.cameras.new('cam')
    cam.type = 'PANO'

    def apply(target):
        target.panorama_type = 'EQUIRECTANGULAR'
        target.longitude_min = math.radians(-180.0)
        target.longitude_max = math.radians(180.0)
        target.latitude_min = math.radians(LAT_MIN)
        target.latitude_max = math.radians(LAT_MAX)

    # Blender 4.x keeps these on the camera data; older builds put them under
    # camera.cycles.
    try:
        apply(cam)
    except (AttributeError, TypeError):
        apply(cam.cycles)

    co = bpy.data.objects.new('cam', cam)
    co.location = (0, 0, 0)
    co.rotation_euler = (math.radians(90), 0, 0)   # level horizon
    bpy.context.collection.objects.link(co)
    bpy.context.scene.camera = co


for i, layer in enumerate(LAYERS):
    name, base, top, scale, detail, density, lo, hi, sun, samples = layer
    reset()
    setup_render(samples)
    build_deck(base, top, scale, detail, density, lo, hi, seed=i + 1)
    build_lights(sun)
    build_camera()

    path = os.path.join(OUT, 'cloud-%s.png' % name)
    bpy.context.scene.render.filepath = path
    print('rendering', name, '->', path)
    bpy.ops.render.render(write_still=True)

print('done')

# Initial feature and data-model map

This map separates verified static evidence from behavior that still needs runtime observation.

## Evidence from the package

| Area | Static evidence | Confidence |
|---|---|---|
| Project/editor navigation | Manifest declares main and edit activities | High |
| Project timeline and animation | DEX strings include scene, scene element, keyable properties, transforms, and keyframe concepts | High |
| Visual layers | Scene element types, shapes, drawings, fills, and blending-mode concepts appear in the compiled strings | High |
| Effects and presets | Effect data assets, shader programs, and preset XML files are bundled | High |
| Text and fonts | Text preset XML and font-thumbnail assets are bundled; a font browser activity is declared | High |
| Media import | Media browser and audio browser activities are declared; manifest includes media permissions | High |
| Export | Export preview and save-to-storage activities are declared | High |
| Audio/video playback and rendering | DEX strings and bundled media/native libraries indicate media pipeline dependencies | Medium |
| Doge-specific changes | Not established by the package inventory alone | Unknown |

## Candidate project model

A new implementation should define its own serializable project model. The packaged sample preset XML suggests the following *behavioral concepts* are important to represent:

- Project canvas dimensions, export dimensions, frame rate, duration, and background.
- Media records with a type, source reference, and metadata.
- Timeline elements with start/end times and a layer/element type.
- Transform properties such as position, scale, rotation, and opacity.
- Keyframed values, interpolation/easing, and property tracks.
- Text content, font selection, alignment, size, and fill.
- Shape paths, fills, gradients, and effects.
- Effect parameters and blend modes.

The preset samples in this APK identify themselves as Alight Motion 3.6.0 exports from 2020. They are useful as examples of a historical project interchange format, but must not be treated as proof that the current 10.0.1 editor uses exactly the same internal format.

## First implementation milestones

1. **Project core:** create/save/open a project with canvas settings and a timeline.
2. **Layer model:** support image, video, audio, text, and shape layer types as independent model objects.
3. **Timeline:** add clip ranges, selection, playback position, and basic trim/move operations.
4. **Animation:** add keyframe tracks for position, scale, rotation, opacity, and easing.
5. **Preview renderer:** render a composition at a requested timestamp.
6. **Effects:** add an effect interface and implement a small number of original effects.
7. **Export:** render frames and mux audio/video using a maintainable media pipeline.

## Still needed

- Screenshots or a screen recording of the Doge Editing home screen and editor.
- A walk-through of creating a project, adding a layer, applying an effect, animating a property, and exporting.
- A clear list of what Doge Editing changes relative to the standard Alight Motion experience.

These observations will determine the UI layout and prioritize what to implement first.

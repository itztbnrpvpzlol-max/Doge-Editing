# Doge Editing — initial APK analysis

## Scope

This is a read-only inventory of the supplied APK. It records package metadata, declared Android permissions/components, DEX and native-library counts, and asset categories. It does not patch the APK, defeat code protection, or redistribute packaged code/assets.

## Verified findings

- Package name: `com.alightcreative.motion`
- Version name: `10.0.1`
- Version code: `9999999`
- Minimum Android SDK: `24`
- Target Android SDK: `36`
- Compile SDK: `36`
- APK size: `97,092,545` bytes
- SHA-256: `97873fabb46e36f6cdcd7ceacd6a4beb7e276faa20f7e18ab2ebb3261f926f32`
- DEX files: `11`
- Native libraries: `38`, for `arm64-v8a` and `armeabi-v7a`
- Assets: `1,459`
- Effect data files (`.ta`): `1,107`
- Shader files: `26`
- Effect preset XML files: `13`
- Code-protection marker files: `3`

## Important Android components

The manifest declares app-owned screens including `MainActivity`, `EditActivity`, `SettingsActivity`, `MediaBrowser`, `AudioBrowserActivity`, `EffectBrowserActivity`, `FontBrowserActivity`, `ColorPickerActivity`, `ExportPreviewActivity`, and `SaveToStorageActivity`.

## Architecture clues

The package includes NanoVG-related rendering libraries, image/GIF processing libraries, OpenGL shader assets, a V8 runtime (Javet), and a large set of effect assets. DEX strings expose scene concepts such as `Scene`, `SceneElement`, `Keyable`, `KeyableTransform`, `CameraProperties`, `GradientFill`, `BlendingMode`, and `Drawing`. These are architecture clues, not a recovered source tree.

## Interpretation

The APK manifest identifies itself as the Alight Motion Android package, version 10.0.1. The inventory does not by itself tell us which customizations distinguish the Doge Editing distribution from the corresponding upstream application. We should map those differences through screenshots, observable workflows, and a permitted reference build rather than assume every bundled feature is a Doge-specific modification.

## Next steps

1. Capture and catalogue the actual Doge Editing UI: home/project list, editor, layer controls, effects, text, audio, and export.
2. Build a feature matrix with observed behavior, inputs, outputs, and dependencies.
3. Design an independent Android implementation and project-file model.
4. Add build/test workflows after the new Android project skeleton is in place.

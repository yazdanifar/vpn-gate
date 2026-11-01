# Golden screenshots of the WinUI app

`VPNGate.UiTests` renders each view in-process with `RenderTargetBitmap` and compares it with the PNG of the same name here
(`UiHost.CompareWithGolden`): at most 0.5 % of the pixels may differ by more than 16 per channel. Every view sees the fixed
time `Rig.Now`, so dates and durations do not change between runs.

The pixels depend on the runner's Windows image, fonts and Windows App SDK, so the images are recorded on CI, never by hand,
and the `winui-ui` job is pinned to `windows-2025`:

1. Run the `Record screenshot goldens` workflow (Actions tab, any branch) or download the `winui-ui-screenshots` artifact of a
   `winui-ui` job whose only failures are golden differences (a test stops at its first difference, so the workflow is the
   way to get every image).
2. Look at the images, copy them here and commit them. The reviewer approves the images in that commit.
3. The `winui-ui` job fails on any later visual change and uploads the actual and `.diff.png` images in `winui-ui-screenshots`.

A deliberate UI change is approved the same way: re-record, review the changed PNGs in the diff, commit.

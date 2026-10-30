# Golden screenshots of the GTK app

`tests/ui.rs` renders each window offscreen (GSK Cairo renderer under Xvfb, DejaVu Sans, Adwaita light) and compares it with the
PNG of the same name here: at most 0.5 % of the pixels may differ by more than 16 per channel.

The pixels depend on the runner's fonts, theme and Cairo, so the images are recorded on CI, never by hand:

1. Run the `GTK goldens` workflow (Actions tab, any branch) or download the `gtk-ui-actual` artifact of any `gtk` job.
2. Look at the images, copy them here and commit them. The reviewer approves the images in that commit.
3. The `gtk` job fails on any later visual change and uploads the actual and diff images as `gtk-ui-actual`.

A deliberate UI change is approved the same way: re-record, review the changed PNGs in the diff, commit.

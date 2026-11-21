# cfs brand mark

A key drawn from masked dots (•••). The dots are what the UI shows wherever a value is hidden.

## Files
| File | Use |
|---|---|
| `cfs-mark.svg` | App icon, sidebar logo, README header. Teal tile, white mark. |
| `cfs-mark-mono.svg` | One-colour use on light backgrounds. Takes its colour from `color`. |
| `cfs-mark-white.svg` | On dark or teal backgrounds, no tile. |
| `cfs-favicon.svg` | Browser tab (scalable). Solid-bow variant, heavier for small sizes. |
| `cfs-favicon-16.svg` | Hand-fitted 16px favicon. Use this one at exactly 16×16. |
| `cfs-apple-touch.svg` | Square, full-bleed. Export as 180×180 PNG for `apple-touch-icon`. |
| `cfs-maskable.svg` | Full-bleed, mark inside the central 80%. Export 192 and 512 PNG for the web manifest. |
| `cfs-lockup.svg` | Mark and wordmark. **Outline the text before shipping.** |

## Construction (64 × 64 grid)
- Tile: `rx 14`. Teal `#0B7A75`. Mark is white.
- Ring: centre (18.1, 30.4), radius 10, stroke 7.
- Dots: radius 5.2, centres at x 40.3 and 54.2. Tooth: radius 4, centre (54.2, 43.1).
- All gaps between shapes are 3.5. Margins left and right are equal (4.6), and so are top and bottom (16.9).
- In the tile the mark is scaled to 87.6% so it reads as large without touching the edges.

## Rules
- Clear space: at least a quarter of the tile width on every side.
- Smallest size: 16px, using `cfs-favicon-16.svg`. Below that, don't use the mark.
- Don't recolour the tile, rotate the mark, or add a lock.
- Wordmark: Space Grotesk Bold, lowercase "cfs", tracking −1.
- The padlock icon stays in the product only to mean "locked".

## Status
Redrawn on a grid and ready to use. The wordmark still needs outlining in a vector editor.

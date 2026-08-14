/**
 * The DIGIPIN precision ladder — the address profile's instance of the
 * core's generic `PrecisionLadder`.
 *
 * Grid geometry lives here rather than in `packages/core` for the same
 * reason the address payload does: the core may not carry address
 * vocabulary, and a geocode grid is address vocabulary. The core knows
 * precision is ordered; this file knows what DIGIPIN's rungs measure.
 *
 * DIGIPIN's geometry, and the provenance of every number below:
 *
 *   - India Post's grid covers a bounding box of latitude 2.5°N–38.5°N and
 *     longitude 63.5°E–99.5°E — 36° on each side.
 *   - Each character subdivides the current cell 4×4, so cell side is
 *     36 / 4^n degrees after n characters.
 *   - The code is 10 characters, giving 36 / 4^10 ≈ 0.0000343°, which at
 *     ~111.32 km per degree is ~3.8 m — matching DoP's published "~4×4 m"
 *     figure. That agreement is the check that this geometry is right.
 *
 * Longitude foreshortens with latitude, so a cell is not square in metres.
 * `REFERENCE_LATITUDE_DEG` is the latitude the area figures are computed
 * at — stated as an assumption rather than buried, because it moves the
 * answer: the same rung is ~6% larger in area at Kanyakumari than at Delhi.
 * A deployment that cares supplies its own latitude.
 */
import {
  assertMonotoneLadder,
  type PrecisionLadder,
  type PrecisionRung,
  type DensityPort,
} from "../../../packages/core/src/core.ts";

const BOX_DEGREES = 36;
const SUBDIVISION = 4;
export const DIGIPIN_CHARS = 10;
const METRES_PER_DEGREE = 111_320;

/**
 * ~20°N — roughly the population-weighted centre of DIGIPIN's box, and the
 * latitude every published cell-size figure in `spec/CFP-v0.x.md` is
 * computed at. Changing this changes those figures.
 */
export const REFERENCE_LATITUDE_DEG = 20;

/** Cell side in degrees after `chars` characters. */
function cellSideDegrees(chars: number): number {
  return BOX_DEGREES / SUBDIVISION ** chars;
}

/**
 * Ground area of one cell at `chars` characters, in km², at
 * `REFERENCE_LATITUDE_DEG`. The longitude side is foreshortened by
 * cos(latitude); the latitude side is not.
 */
export function digipinCellKm2(chars: number, atLatitudeDeg = REFERENCE_LATITUDE_DEG): number {
  const sideDeg = cellSideDegrees(chars);
  const northSouthM = sideDeg * METRES_PER_DEGREE;
  const eastWestM = northSouthM * Math.cos((atLatitudeDeg * Math.PI) / 180);
  return (northSouthM * eastWestM) / 1_000_000;
}

/** The full ladder, coarsest first — one rung per disclosed character. */
export const DIGIPIN_LADDER: PrecisionLadder = Object.freeze(
  Array.from({ length: DIGIPIN_CHARS }, (_, i): PrecisionRung => {
    const chars = i + 1;
    return { chars, cellKm2: digipinCellKm2(chars) };
  }),
);

assertMonotoneLadder(DIGIPIN_LADDER);

/**
 * A flat density, for the demo and for tests. Named for what it is: a
 * deployment that used this in production would be asserting that India has
 * uniform population density, which it emphatically does not. A real
 * implementation of `DensityPort` reads census or operator data keyed by the
 * code's own prefix.
 */
export class FlatDensity implements DensityPort {
  #peoplePerKm2: number;
  constructor(peoplePerKm2: number) {
    this.#peoplePerKm2 = peoplePerKm2;
  }
  peoplePerKm2(): number {
    return this.#peoplePerKm2;
  }
}

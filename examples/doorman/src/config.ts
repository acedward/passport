/*
 * Everything Doorman needs to know about the outside world.
 *
 * The Passport origin is not a default worth guessing wrong: a mistyped origin
 * is a silent failure, because a message sent to the wrong origin is simply
 * never delivered and never answered. Override both values with a `.env.local`
 * when running against something other than the local Passport.
 */

export const PASSPORT_ORIGIN: string =
  import.meta.env.VITE_PASSPORT_ORIGIN ?? 'http://localhost:5175';

/**
 * Where the door fee is paid to. Never shown on screen — it is not copy.
 *
 * `null` when this build was given no account, and there is deliberately no
 * placeholder to fall back on: a made-up address turns a missing setting into
 * a payment Passport refuses for reasons that have nothing to do with the
 * door. Doorman says so on screen and does not offer the payment at all.
 */
export const DOORMAN_ACCOUNT: string | null =
  import.meta.env.VITE_DOORMAN_ACCOUNT ?? null;

/**
 * The price of entry, in atomic NIGHT, as a base-10 string — which is what the
 * wire protocol carries. One NIGHT is 1,000,000 atomic units (`NIGHT_DECIMALS`
 * is 6 in `@midnight-passport/connect`), so this is 0.1 NIGHT. Render it with
 * the package's `formatNight`; never divide it.
 */
export const DOOR_FEE = '100000';

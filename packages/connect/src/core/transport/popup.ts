/* ===========================================================================
 * The pop-up channel — the app opened Passport
 * ===========================================================================
 *
 * The app mints the pair and hands it to Passport on the launch URL; Passport
 * echoes it back in `ready`, which is the app's signal that the window is
 * listening. Two launch contracts, one per exchange, and the parameter names
 * are what keep them apart:
 *
 *   profile  ?passportRequestId=&passportNonce=
 *   payment  ?passportTxRequestId=&passportTxNonce=
 *
 * Passport arms exactly one consent surface per window load, from whichever
 * pair of parameters it was given. BOTH surfaces announce themselves with the
 * same `passport.profile.ready` message, so the PAIR — not the message type —
 * is what tells the app which question is being answered. This transport
 * matches on it, always.
 *
 * ONE WINDOW, ONE NAME. `midnight-passport` is the window name, so a payment
 * reuses the Passport the user already connected with instead of stacking a
 * second one beside it. Passport restores its session across that navigation
 * without a further ceremony; the passkey is asked for at approval, which is
 * where it belongs.
 *
 * A CLOSED WINDOW NEVER ANSWERS, and no message says it closed. The only way
 * to find out is to ask, so `closed()` is a poll. Without it, a user who
 * dismisses the Passport window leaves the calling button disabled forever.
 * ========================================================================= */

import { parsePassportProfileReady } from '../../protocol/profile.js';
import { randomExchangePair } from '../random.js';
import {
  PassportTransportError,
  type PassportChannel,
  type PassportExchangeKind,
  type PassportExchangePair,
  type PassportPresence,
  type PassportTransport,
} from './types.js';

/** One name means one window. */
export const PASSPORT_WINDOW_NAME = 'midnight-passport';

/** The launch query parameter names, per exchange. */
export const PASSPORT_LAUNCH_PARAMS = {
  profile: { requestId: 'passportRequestId', nonce: 'passportNonce' },
  tx: { requestId: 'passportTxRequestId', nonce: 'passportTxNonce' },
} as const;

export interface PopupTransportOptions {
  readonly origin: string;
  /** How long to wait for the opened window to echo the pair back. */
  readonly readyTimeoutMs: number;
  /** How often the window is checked for having been closed. */
  readonly closedPollMs: number;
  readonly features?: string;
  readonly window?: Window;
  readonly onTraffic?: (direction: 'in' | 'out', type: string, payload: unknown) => void;
  /** Called with the pair each time the opened window announces itself. */
  readonly onReady?: (pair: PassportExchangePair) => void;
}

export function createPopupTransport(options: PopupTransportOptions): PassportTransport {
  const host = options.window ?? window;
  const handlers = new Set<(data: unknown) => void>();
  /** Waiters on a `ready` echoing one specific pair. */
  const readyWaiters = new Map<string, (pair: PassportExchangePair) => void>();
  let popup: Window | null = null;
  let attached = false;

  const key = (pair: PassportExchangePair) => `${pair.requestId}\0${pair.nonce}`;

  const onMessage = (event: MessageEvent): void => {
    /* Two gates before anything is parsed: the pinned origin, and the window
       we opened ourselves. */
    if (event.origin !== options.origin || event.source !== popup) return;

    const ready = parsePassportProfileReady(event.data);
    if (ready) {
      options.onTraffic?.('in', ready.type, ready);
      options.onReady?.({ requestId: ready.requestId, nonce: ready.nonce });
      const waiter = readyWaiters.get(key(ready));
      if (waiter) {
        readyWaiters.delete(key(ready));
        waiter({ requestId: ready.requestId, nonce: ready.nonce });
      }
      return;
    }
    for (const handler of handlers) handler(event.data);
  };

  const attach = (): void => {
    if (attached) return;
    attached = true;
    host.addEventListener('message', onMessage);
  };

  return {
    mode: 'popup',

    listen(handler) {
      attach();
      handlers.add(handler);
      return () => handlers.delete(handler);
    },

    async open(kind: PassportExchangeKind, signal: AbortSignal): Promise<PassportChannel> {
      if (kind === 'incentive') {
        /* There is nothing to post to. An incentive report is a message to the
           Passport that is HOSTING the app, and a pop-up is not hosting
           anything — see `reportIncentive`, which says so rather than
           pretending it sent something. */
        throw new PassportTransportError(
          'not-present',
          'An incentive report only exists inside Passport’s own app browser.',
        );
      }
      attach();
      const pair = randomExchangePair();
      const names = kind === 'profile' ? PASSPORT_LAUNCH_PARAMS.profile : PASSPORT_LAUNCH_PARAMS.tx;
      const query = new URLSearchParams({
        [names.requestId]: pair.requestId,
        [names.nonce]: pair.nonce,
      });

      const opened = host.open(
        `${options.origin}/?${query.toString()}`,
        PASSPORT_WINDOW_NAME,
        options.features ?? 'popup,width=620,height=780',
      );
      if (!opened) {
        /* No window, no approval sheet, no payment. Say so; do not pretend. */
        throw new PassportTransportError(
          'popup-blocked',
          'The browser blocked the Passport window.',
        );
      }
      popup = opened;
      opened.focus();

      await new Promise<void>((resolve, reject) => {
        const settle = (outcome: () => void) => {
          readyWaiters.delete(key(pair));
          host.clearTimeout(timer);
          host.clearInterval(poll);
          signal.removeEventListener('abort', onAbort);
          outcome();
        };
        const onAbort = () =>
          settle(() =>
            reject(new PassportTransportError('timed-out', 'The exchange was abandoned.')),
          );
        const timer = host.setTimeout(() => {
          settle(() =>
            reject(
              new PassportTransportError('timed-out', 'The Passport window never announced itself.'),
            ),
          );
        }, options.readyTimeoutMs);
        const poll = host.setInterval(() => {
          if (opened.closed) {
            settle(() =>
              reject(
                new PassportTransportError(
                  'passport-closed',
                  'The Passport window was closed before it announced itself.',
                ),
              ),
            );
          }
        }, options.closedPollMs);
        readyWaiters.set(key(pair), () => settle(resolve));
        signal.addEventListener('abort', onAbort, { once: true });
      });

      return {
        pair,
        post: (message: object) => {
          options.onTraffic?.(
            'out',
            String((message as { type?: unknown }).type ?? 'unknown'),
            message,
          );
          opened.postMessage(message, options.origin);
        },
        closed: () => opened.closed,
        release: () => {
          readyWaiters.delete(key(pair));
        },
      };
    },

    async presence(): Promise<PassportPresence> {
      /* The honest answer, and this package will not launder it into a boolean.
         There is no injected provider to look for — a page on another origin
         cannot receive `window.midnight.*`, and Passport deliberately does not
         weaken the same-origin policy to provide one. Finding out costs a
         window, and a window costs a user gesture. The recommended pattern is
         therefore: render the button, let the user press it, and handle
         `popup-blocked` and `passport-closed` when they happen. */
      return {
        present: 'unknown',
        reason: 'popup-mode',
        message:
          'Whether Passport is installed cannot be known from this page. There is no injected provider across origins, so the only way to find out is to open the window — which needs the user to press something.',
      };
    },

    destroy() {
      if (attached) host.removeEventListener('message', onMessage);
      attached = false;
      handlers.clear();
      readyWaiters.clear();
      popup = null;
    },
  };
}

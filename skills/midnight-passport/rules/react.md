# React bindings — `@midnight-passport/connect/react`

Peer dependency: `react`. Source: `packages/connect/src/react/index.tsx`.

## `<PassportProvider origin="…">`

Put it at the root. It owns exactly one client for the life of the tree — a
second client means a second message listener and two windows both claiming
to be Passport. It accepts every `CreatePassportOptions` field as a prop
(`origin`, `transport`, `timeoutMs`, `presenceTimeoutMs`, `closedPollMs`,
`popupFeatures`).

```tsx
import { PassportProvider } from '@midnight-passport/connect/react';

<PassportProvider origin={import.meta.env.VITE_PASSPORT_ORIGIN}>
  <App />
</PassportProvider>
```

## `usePassport({ detect?, trafficLimit? })`

```ts
{ passport: Passport; mode: 'iframe' | 'popup'; presence: PassportPresence | null; traffic: PassportTrafficEvent[] }
```

`presence` is `null` until the first detection settles (`detect: false`
skips it). `traffic` is the message transcript, newest last, capped at
`trafficLimit` (default 24). Render it in a dev panel.

## `usePassportProfile(fields)`

```ts
{ request(): Promise<PassportProfileResult>; result: PassportProfileResult | null; pending: boolean; reset(): void }
```

`fields` may be an inline array literal; the hook keys on the values, not
the array identity.

## `usePassportPayment()`

```ts
{
  request(intent: PassportPaymentIntent): Promise<PassportPaymentResult>;
  reportIncentive(incentive: PassportIncentive): Promise<PassportIncentiveResult>;
  result: PassportPaymentResult | null;
  pending: boolean;
  reset(): void;
}
```

## Patterns

```tsx
function Door() {
  const { presence, mode } = usePassport();
  const profile = usePassportProfile(['displayName', 'passportContract']);
  const payment = usePassportPayment();

  return (
    <>
      <button disabled={profile.pending} onClick={() => void profile.request()}>
        Continue with Passport
      </button>
      {profile.result && !profile.result.approved && <p>{profile.result.message}</p>}
      {profile.result?.approved && (
        <p>
          Welcome, {profile.result.profile.displayName ?? 'friend'}.
          {profile.result.withheld.length > 0 && ' Some details were not shared.'}
        </p>
      )}
      <button
        disabled={payment.pending}
        onClick={() => void payment.request({ recipientAddress: DOOR, amount: '100000', purpose: 'Cover charge' })}
      >
        Pay 0.1 NIGHT
      </button>
      {payment.result?.status === 'submitted' && (
        <p>Paid. {payment.result.sponsored ? 'Network fee covered.' : ''}</p>
      )}
      {payment.result && payment.result.status !== 'submitted' && <p>{payment.result.message}</p>}
    </>
  );
}
```

- Call `request()` from the click handler, not from an effect: in pop-up mode
  the window needs a user gesture.
- Do not derive "signed in" from anything but `result.approved === true`.
- `reset()` clears the last result; it does not cancel an exchange in flight.

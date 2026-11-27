'use client';

export default function Error({ reset }) {
  return <section className="page-error" role="alert"><h1>This view could not load</h1><p>This problem does not change follow-ups that were already saved. Anything not yet saved may need to be entered again.</p><button className="secondary-button" onClick={reset}>Try again</button></section>;
}

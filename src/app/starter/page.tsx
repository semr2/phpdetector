export default function StarterPage() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-950 px-6 py-16 text-white">
      <section className="w-full max-w-2xl rounded-2xl border border-white/10 bg-white/5 p-8 shadow-2xl sm:p-12">
        <p className="mb-3 text-sm font-semibold uppercase tracking-[0.2em] text-cyan-300">
          HTML starter
        </p>
        <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">Hello, world!</h1>
        <p className="mt-5 max-w-prose leading-7 text-slate-300">
          Your starter page is running. Use this page as a place to begin building your website.
        </p>
        <a
          className="mt-8 inline-flex rounded-lg bg-cyan-300 px-5 py-3 font-semibold text-slate-950 transition hover:bg-cyan-200 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-cyan-300"
          href="/"
        >
          Return to the scanner dashboard
        </a>
      </section>
    </main>
  );
}

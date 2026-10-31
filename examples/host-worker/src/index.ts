/** Reference host arrives at step 15 of the build sequence. */
export default {
  fetch(): Response {
    return new Response("kavach reference host: not built yet", { status: 501 });
  }
};

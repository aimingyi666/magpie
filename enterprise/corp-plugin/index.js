// The plugin host's part of the corporate client.
//
// It does two things magpie needs at load time — the provider the
// corporation hands out (its `config` hook) and the sign-in that gives it
// a key (`auth`) — and starts a loopback service for the page, where
// sync state and the four jobs live.
//
// The page is served by that same service: magpie hands a plugin page a
// frame with connect-src 'none', so page/index.html redirects to the
// service, which draws it.
import { loadCorpConfig, stateDirectory } from "./src/config.mjs";
import { createStore } from "./src/store.mjs";
import { providerConfig, providerModels } from "./src/providers.mjs";
import { createJoiner } from "./src/auth.mjs";
import { startService } from "./src/service.mjs";

// boot starts the plugin's own parts once: the store, the config and the
// joiner, and a loopback service for the page. The service is started on
// first use, so a plugin host with no page open starts no server.
let runtime;

function boot(options = {}) {
  if (runtime) return runtime;
  const dir = stateDirectory();
  const config = loadCorpConfig(dir, options);
  const store = createStore(dir);
  const joiner = createJoiner({ config, store, dir });
  runtime = {
    dir,
    config,
    store,
    joiner,
    service: null,
    startService() {
      if (!this.service) {
        this.service = startService({ config, store, joiner, dir });
      }
      return this.service;
    },
  };
  return runtime;
}

export default async function corp(input, options = {}) {
  const rt = boot(options);
  const provider = rt.config.providerId;
  // the page's own service, without which the page has nothing to ask
  rt.startService().ready.catch(() => {});

  return {
    // The provider the corporation hands out. `apiKey` authorize runs the
    // browser sign-in and answers the device token, which magpie keeps as
    // an ordinary gateway key.
    auth: {
      provider,
      methods: [
        {
          type: "api",
          label: "Corp sign-in",
          // A device that still works is handed over as it is, so signing
          // in from the page first makes this instant; otherwise the
          // browser flow runs here.
          authorize: async () => ({ key: (await rt.joiner.current()).deviceToken }),
        },
      ],
    },

    // The provider's own name, base and models, read from the bundle the
    // last sync kept. A host started before the first sync has none: the
    // provider is listed by its sign-in alone until magpie restarts.
    config: (cfg) => providerConfig(cfg, { provider, dir: rt.dir, config: rt.config, store: rt.store }),

    // What magpie asks on every listing: the bundle's models, so a model
    // the corporation adds shows without a restart.
    provider: {
      models: async () => providerModels({ provider, dir: rt.dir, config: rt.config }),
    },
  };
}

// Exported for the tests and for `magpie plugin` diagnostics: what this
// host would boot with.
export { boot };

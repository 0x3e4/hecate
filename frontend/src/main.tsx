import React from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider } from "react-router-dom";

import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "./styles.css";
import "./ui/primitives.css";

import { router } from "./router";
import { I18nProvider } from "./i18n/context";
import { TimezoneProvider } from "./timezone/context";
import { ServerConfigProvider } from "./server-config/context";


document.documentElement.classList.add("js");

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <I18nProvider>
      <TimezoneProvider>
        <ServerConfigProvider>
          <RouterProvider router={router} />
        </ServerConfigProvider>
      </TimezoneProvider>
    </I18nProvider>
  </React.StrictMode>
);

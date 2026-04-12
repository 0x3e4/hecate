import React from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider } from "react-router-dom";

import { router } from "./router";
import { I18nProvider } from "./i18n/context";
import { TimezoneProvider } from "./timezone/context";
import { ServerConfigProvider } from "./server-config/context";

import "./styles.css";

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

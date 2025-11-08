import axios from "axios";

const baseURL = import.meta.env.VITE_API_BASE_URL ?? "/api";

export const api = axios.create({
  baseURL,
  timeout: 60000  // Increased to 60s to handle long-running operations like stats
});

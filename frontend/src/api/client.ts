import axios from "axios";

const BASE = import.meta.env.VITE_API_BASE || "/api/v1";

const tokenKey = "cs_token";

export const getToken = () => localStorage.getItem(tokenKey);
export const setToken = (t: string) => localStorage.setItem(tokenKey, t);
export const clearToken = () => localStorage.removeItem(tokenKey);

export const api = axios.create({ baseURL: BASE });

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (r) => r,
  (error) => {
    if (error.response && error.response.status === 401) {
      clearToken();
      if (!location.pathname.includes("/login")) location.href = "/login";
    }
    return Promise.reject(error);
  }
);

export const errText = (e: unknown): string => {
  const err = e as { response?: { data?: { error?: { message?: string } } }, message?: string };
  return err?.response?.data?.error?.message || err?.message || "Request failed";
};

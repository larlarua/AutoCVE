/**
 * Deployment-specific UI branding.
 *
 * Vite embeds this value when the frontend is built. Keep the default false
 * for the public AutoCVE distribution; internal AIAudit deployments opt in.
 */
export const internalBrandingEnabled = import.meta.env.VITE_INTERNAL_BRANDING === "true";

export const productName = internalBrandingEnabled ? "AIAudit" : "AutoCVE";
export const workspaceBrandName = `${productName} Workspace`;
export const defaultLandingPath = internalBrandingEnabled ? "/dashboard" : "/";

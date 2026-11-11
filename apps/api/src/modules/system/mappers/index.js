/**
 * Maps internal records to public DTOs. Never return internal objects directly from controllers.
 * @param {{ name: string, description: string, prefix: string }} module
 */
export const toModuleDto = ({ name, description, prefix }) => ({ name, description, prefix });

/**
 * @param {{ name: string, version: string, environment: string }} app
 * @param {string} apiVersion
 */
export const toInfoDto = ({ name, version, environment }, apiVersion) => ({
  name,
  version,
  environment,
  apiVersion,
});

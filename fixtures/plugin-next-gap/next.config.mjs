const profile = process.env.FIXTURE_PROFILE;
const configuration = await import(`./profiles/${profile}.mjs`);

export default configuration.default;

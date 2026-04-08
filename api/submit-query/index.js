const crypto = require('crypto');
const { getContainer } = require('../shared/cosmos');
const { ALLOWED_SERVICES, isValidEmail, sanitizePayload } = require('../shared/validation');

module.exports = async function (context, req) {
  try {
    const payload = sanitizePayload(req.body || {});

    if (payload.website) {
      return {
        status: 400,
        body: { error: 'Invalid submission.' }
      };
    }

    if (!payload.name || !payload.email || !payload.serviceInterestedIn || !payload.message) {
      return {
        status: 400,
        body: { error: 'Name, email, service, and message are required.' }
      };
    }

    if (!isValidEmail(payload.email)) {
      return {
        status: 400,
        body: { error: 'Please enter a valid email address.' }
      };
    }

    if (!ALLOWED_SERVICES.includes(payload.serviceInterestedIn)) {
      return {
        status: 400,
        body: { error: 'Please select a valid service.' }
      };
    }

    const item = {
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
      status: 'New',
      name: payload.name,
      company: payload.company,
      email: payload.email,
      phone: payload.phone,
      serviceInterestedIn: payload.serviceInterestedIn,
      message: payload.message,
      sourcePage: 'contact',
      ownerNotes: ''
    };

    const container = getContainer();
    await container.items.create(item);

    return {
      status: 201,
      body: { success: true, id: item.id }
    };
  } catch (error) {
    context.log.error(error);
    return {
      status: 500,
      body: { error: 'Unable to store the query right now.' }
    };
  }
};

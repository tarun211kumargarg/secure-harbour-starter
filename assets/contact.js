const contactForm = document.querySelector('[data-query-form]');
const notice = document.querySelector('[data-form-notice]');

function showNotice(message, type) {
  if (!notice) return;
  notice.textContent = message;
  notice.className = `notice show ${type}`;
}

async function submitQuery(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submitButton = form.querySelector('button[type="submit"]');
  const formData = new FormData(form);
  const payload = Object.fromEntries(formData.entries());

  if (payload.website) {
    showNotice('Your message could not be submitted.', 'error');
    return;
  }

  submitButton.disabled = true;
  submitButton.textContent = 'Submitting...';

  try {
    const response = await fetch('/api/submit-query', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.error || 'Unable to submit your query right now.');
    }

    window.location.href = '/thank-you';
  } catch (error) {
    showNotice(error.message || 'Something went wrong. Please try again.', 'error');
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = 'Submit Query';
  }
}

if (contactForm) {
  contactForm.addEventListener('submit', submitQuery);
}

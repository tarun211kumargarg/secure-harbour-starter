'use strict';

const API_URL = 'https://models.github.ai/inference/chat/completions';

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is missing`);
  }
  return value;
}

async function createChatCompletion(messages) {
  const token = requiredEnv('GITHUB_TOKEN');
  const model = process.env.LLM_MODEL || 'openai/gpt-4.1';

  const response = await fetch(API_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/vnd.github+json',
      'Authorization': `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28'
    },
    body: JSON.stringify({
      model,
      messages,
      temperature: 0.1
    })
  });

  const text = await response.text();

  if (!response.ok) {
    throw new Error(`GitHub Models API error ${response.status}: ${text}`);
  }

  return JSON.parse(text);
}

function getAssistantText(response) {
  return response?.choices?.[0]?.message?.content || '';
}

module.exports = {
  createChatCompletion,
  getAssistantText
};
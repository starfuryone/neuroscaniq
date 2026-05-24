// PM2 ecosystem -- optional alternative to Docker for bare-metal deploys.
// Usage: pm2 start ecosystem.config.js
//
// Assumes a system Python venv at backend/.venv and node installed for the
// front-end. Run `cd frontend && npm run build` first.

module.exports = {
  apps: [
    {
      name: 'nsiq-api',
      cwd: './backend',
      script: '.venv/bin/uvicorn',
      args: 'app.main:app --host 0.0.0.0 --port 8000 --workers 4',
      env: { PYTHONUNBUFFERED: '1' },
      max_memory_restart: '1G',
    },
    {
      name: 'nsiq-worker-scan',
      cwd: './backend',
      script: '.venv/bin/python',
      args: '-m app.workers.runner --queue scan',
      instances: 2,
      exec_mode: 'fork',
    },
    {
      name: 'nsiq-worker-screenshot',
      cwd: './backend',
      script: '.venv/bin/python',
      args: '-m app.workers.runner --queue screenshot',
      max_memory_restart: '1G',
    },
    {
      name: 'nsiq-worker-monitor',
      cwd: './backend',
      script: '.venv/bin/python',
      args: '-m app.workers.runner --queue monitor',
    },
    {
      name: 'nsiq-worker-alert',
      cwd: './backend',
      script: '.venv/bin/python',
      args: '-m app.workers.runner --queue alert',
    },
    {
      name: 'nsiq-frontend',
      cwd: './frontend',
      script: 'node',
      args: '.next/standalone/server.js',
      env: { NODE_ENV: 'production', PORT: '3000' },
      max_memory_restart: '1G',
    },
  ],
};

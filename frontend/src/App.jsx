import React, { useState } from 'react';
import Dashboard from './pages/Dashboard';
import SplashScreen from './pages/SplashScreen';

const SPLASH_KEY = 'dnsentinel.splashSeen';

// Show the intro once per browser session; storage can throw in private mode.
const splashSeen = () => {
  try { return sessionStorage.getItem(SPLASH_KEY) === '1'; } catch { return false; }
};

function App() {
  const [booted, setBooted] = useState(splashSeen);

  const handleComplete = () => {
    try { sessionStorage.setItem(SPLASH_KEY, '1'); } catch { /* non-essential */ }
    setBooted(true);
  };

  return booted ? <Dashboard /> : <SplashScreen onComplete={handleComplete} />;
}

export default App;

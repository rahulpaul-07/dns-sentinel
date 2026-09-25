import React, { useState, useEffect, useCallback } from 'react';

const BOOT_SEQUENCE = [
  { text: "CONNECTING TO DETECTION API...", delay: 0 },
  { text: "LOADING 22-FEATURE EXTRACTOR...", delay: 200 },
  { text: "LOADING RANDOM FOREST + ISOLATION FOREST...", delay: 400 },
  { text: "APPLYING CALIBRATED DECISION THRESHOLD...", delay: 600 },
  { text: "ATTACHING SSE TELEMETRY STREAM...", delay: 800 },
  { text: "READY.", delay: 1000 },
];

const LOGO_AT_MS = 1300;
const EXIT_AT_MS = 2200;
const FADE_MS = 400;

const SplashScreen = ({ onComplete }) => {
  const [visibleLines, setVisibleLines] = useState([]);
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState('boot'); // boot | logo | exit
  const [scanLine, setScanLine] = useState(0);

  const finish = useCallback(() => {
    setPhase('exit');
    setTimeout(onComplete, FADE_MS);
  }, [onComplete]);

  useEffect(() => {
    const timers = BOOT_SEQUENCE.map((item, i) => setTimeout(() => {
      setVisibleLines(prev => [...prev, item.text]);
      setProgress(Math.round(((i + 1) / BOOT_SEQUENCE.length) * 100));
    }, item.delay));
    timers.push(setTimeout(() => setPhase('logo'), LOGO_AT_MS));
    timers.push(setTimeout(finish, EXIT_AT_MS));
    const scanInterval = setInterval(() => setScanLine(prev => (prev + 1) % 100), 30);

    // Any key or click skips the intro.
    window.addEventListener('keydown', finish, { once: true });
    window.addEventListener('pointerdown', finish, { once: true });
    return () => {
      timers.forEach(clearTimeout);
      clearInterval(scanInterval);
      window.removeEventListener('keydown', finish);
      window.removeEventListener('pointerdown', finish);
    };
  }, [finish]);

  return (
    <div
      className="fixed inset-0 z-50 overflow-hidden"
      style={{
        background: 'radial-gradient(ellipse at center, #050a12 0%, #020408 100%)',
        opacity: phase === 'exit' ? 0 : 1,
        transition: 'opacity 0.6s ease',
      }}
    >
      {/* Animated grid background */}
      <div style={{
        position: 'absolute', inset: 0, opacity: 0.04,
        backgroundImage: `
          linear-gradient(rgba(0,242,255,0.5) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0,242,255,0.5) 1px, transparent 1px)
        `,
        backgroundSize: '40px 40px',
      }}/>

      {/* Scan line effect */}
      <div style={{
        position: 'absolute', left: 0, right: 0, height: '2px',
        top: `${scanLine}%`,
        background: 'linear-gradient(90deg, transparent, rgba(0,242,255,0.15), transparent)',
        transition: 'top 0.03s linear',
        pointerEvents: 'none',
      }}/>

      {/* Radial glow */}
      <div style={{
        position: 'absolute', inset: 0,
        background: 'radial-gradient(ellipse at 50% 50%, rgba(0,242,255,0.04) 0%, transparent 70%)',
        pointerEvents: 'none',
      }}/>

      {phase === 'boot' ? (
        /* Boot Terminal */
        <div style={{
          position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
          justifyContent: 'center', alignItems: 'flex-start',
          padding: '10%',
        }}>
          {/* Logo top-left */}
          <div style={{ marginBottom: '40px' }}>
            <div style={{
              fontFamily: 'monospace', fontSize: '11px', letterSpacing: '0.3em',
              color: 'rgba(0,242,255,0.5)', marginBottom: '8px',
            }}>DNSENTINEL // STARTING (CLICK TO SKIP)</div>
            <div style={{
              width: '60px', height: '2px',
              background: 'linear-gradient(90deg, #00f2ff, transparent)',
            }}/>
          </div>

          {/* Boot lines */}
          <div style={{ fontFamily: 'monospace', fontSize: '12px', lineHeight: '2', maxWidth: '600px' }}>
            {visibleLines.map((line, i) => (
              <div
                key={i}
                style={{
                  color: i === visibleLines.length - 1 ? '#00f2ff' : 'rgba(0,242,255,0.35)',
                  opacity: 1,
                  animation: 'fadeIn 0.2s ease',
                  display: 'flex', alignItems: 'center', gap: '12px',
                }}
              >
                <span style={{ color: 'rgba(0,242,255,0.2)' }}>{String(i).padStart(2,'0')}</span>
                <span style={{ color: 'rgba(0,242,255,0.2)' }}>›</span>
                <span>{line}</span>
                {i === visibleLines.length - 1 && (
                  <span style={{ animation: 'blink 0.7s step-end infinite' }}>█</span>
                )}
              </div>
            ))}
          </div>

          {/* Progress bar */}
          <div style={{ marginTop: '48px', width: '400px' }}>
            <div style={{
              display: 'flex', justifyContent: 'space-between', marginBottom: '8px',
              fontFamily: 'monospace', fontSize: '10px', color: 'rgba(0,242,255,0.4)',
              letterSpacing: '0.2em',
            }}>
              <span>LOADING</span>
              <span>{progress}%</span>
            </div>
            <div style={{
              height: '2px', background: 'rgba(255,255,255,0.05)', borderRadius: '999px', overflow: 'hidden',
            }}>
              <div style={{
                height: '100%', width: `${progress}%`,
                background: 'linear-gradient(90deg, #00f2ff, #8b5cf6)',
                transition: 'width 0.3s ease',
                boxShadow: '0 0 10px rgba(0,242,255,0.8)',
              }}/>
            </div>
          </div>
        </div>
      ) : (
        /* Logo reveal phase */
        <div style={{
          position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
          justifyContent: 'center', alignItems: 'center', gap: '32px',
        }}>
          {/* Shield icon */}
          <div style={{
            position: 'relative',
            animation: 'scaleIn 0.5s cubic-bezier(0.34, 1.56, 0.64, 1)',
          }}>
            <div style={{
              width: '100px', height: '100px', borderRadius: '50%',
              background: 'radial-gradient(circle, rgba(0,242,255,0.15) 0%, transparent 70%)',
              border: '1px solid rgba(0,242,255,0.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              position: 'relative',
              boxShadow: '0 0 60px rgba(0,242,255,0.15), inset 0 0 40px rgba(0,242,255,0.05)',
              animation: 'pulse 2s ease infinite',
            }}>
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#00f2ff" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="m9 12 2 2 4-4" strokeWidth="1.5"/>
              </svg>
            </div>
            {/* Orbiting ring */}
            <div style={{
              position: 'absolute', inset: '-16px',
              border: '1px solid rgba(0,242,255,0.1)',
              borderRadius: '50%',
              animation: 'spin 8s linear infinite',
            }}>
              <div style={{
                position: 'absolute', top: '-3px', left: '50%', transform: 'translateX(-50%)',
                width: '6px', height: '6px', borderRadius: '50%',
                background: '#00f2ff',
                boxShadow: '0 0 10px #00f2ff',
              }}/>
            </div>
          </div>

          {/* Title */}
          <div style={{ textAlign: 'center', animation: 'fadeInUp 0.6s ease 0.2s both' }}>
            <div style={{
              fontSize: '48px', fontWeight: '900',
              fontFamily: 'system-ui, sans-serif',
              letterSpacing: '-0.02em',
              color: 'white',
              lineHeight: 1,
            }}>
              DNS<span style={{ color: '#00f2ff' }}>entinel</span>
            </div>
            <div style={{
              marginTop: '12px', fontSize: '11px', letterSpacing: '0.5em',
              color: 'rgba(0,242,255,0.5)', fontFamily: 'monospace',
              textTransform: 'uppercase',
            }}>
              Threat Intelligence Platform
            </div>
          </div>

          {/* Tagline */}
          <div style={{ animation: 'fadeInUp 0.6s ease 0.4s both', textAlign: 'center' }}>
            <div style={{
              fontSize: '13px', color: 'rgba(255,255,255,0.3)',
              fontFamily: 'monospace', letterSpacing: '0.1em',
            }}>
              Real-Time DNS Exfiltration Detection & Forensic Analysis
            </div>
          </div>

          {/* Loading dots */}
          <div style={{ display: 'flex', gap: '8px', animation: 'fadeIn 0.5s ease 0.6s both' }}>
            {[0,1,2].map(i => (
              <div key={i} style={{
                width: '6px', height: '6px', borderRadius: '50%',
                background: '#00f2ff',
                animation: `bounce 1s ease ${i * 0.2}s infinite`,
                opacity: 0.7,
              }}/>
            ))}
          </div>
        </div>
      )}

      <style>{`
        @keyframes fadeIn { from { opacity: 0 } to { opacity: 1 } }
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px) } to { opacity: 1; transform: translateY(0) } }
        @keyframes scaleIn { from { opacity: 0; transform: scale(0.5) } to { opacity: 1; transform: scale(1) } }
        @keyframes pulse { 0%,100% { box-shadow: 0 0 60px rgba(0,242,255,0.15), inset 0 0 40px rgba(0,242,255,0.05) } 50% { box-shadow: 0 0 80px rgba(0,242,255,0.25), inset 0 0 50px rgba(0,242,255,0.1) } }
        @keyframes spin { from { transform: rotate(0deg) } to { transform: rotate(360deg) } }
        @keyframes blink { 0%,100% { opacity:1 } 50% { opacity:0 } }
        @keyframes bounce { 0%,100% { transform: translateY(0) } 50% { transform: translateY(-8px) } }
      `}</style>
    </div>
  );
};

export default SplashScreen;

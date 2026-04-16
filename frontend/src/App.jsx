import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Header from './components/Header';
import HomePage from './pages/HomePage';
import ResultPage from './pages/ResultPage';
import HistoryPage from './pages/HistoryPage';

function App() {
  const [analysisResult, setAnalysisResult] = useState(null);

  return (
    <Router>
      <div className="min-h-screen bg-surface-950 bg-grid bg-radial-glow">
        <Header />
        <main className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 pb-16">
          <Routes>
            <Route
              path="/"
              element={<HomePage onResult={setAnalysisResult} />}
            />
            <Route
              path="/result"
              element={<ResultPage result={analysisResult} />}
            />
            <Route path="/history" element={<HistoryPage />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;

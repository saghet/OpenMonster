import React, { useState, useEffect } from 'react';
import {
  BrainCircuit,
  Cpu,
  AlertCircle,
  Sparkles,
  ListOrdered,
  Code2,
  Send,
  RotateCcw,
  Bot,
  Copy,
  Check
} from 'lucide-react';
import { OllamaStatus, Vulnerability } from '../types';
import { apiService } from '../services/api';

interface AISecurityAssistantProps {
  vulnerabilities: Vulnerability[];
}

export const AISecurityAssistant: React.FC<AISecurityAssistantProps> = ({
  vulnerabilities,
}) => {
  const [ollamaStatus, setOllamaStatus] = useState<OllamaStatus>({
    available: false,
    models: [],
  });
  const [selectedModel, setSelectedModel] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'explain' | 'prioritize' | 'code_review'>('explain');
  const [loading, setLoading] = useState<boolean>(false);
  const [statusLoading, setStatusLoading] = useState<boolean>(false);

  // Tab 1 state
  const [selectedVulnId, setSelectedVulnId] = useState<string>(vulnerabilities[0]?.id || '');
  const [aiExplainResponse, setAiExplainResponse] = useState<string>('');

  // Tab 2 state
  const [aiPrioritizeResponse, setAiPrioritizeResponse] = useState<string>('');

  // Tab 3 state
  const [insecureCode, setInsecureCode] = useState<string>(
    '# Ejemplo vulnerable:\nquery = f"SELECT * FROM users WHERE username = \'{user_input}\'"\ncursor.execute(query)'
  );
  const [codeReviewResponse, setCodeReviewResponse] = useState<string>('');
  const [copied, setCopied] = useState<boolean>(false);

  useEffect(() => {
    checkStatus();
  }, []);

  const checkStatus = async () => {
    setStatusLoading(true);
    try {
      const status = await apiService.checkOllamaStatus();
      setOllamaStatus(status);
      if (status.models.length > 0 && !selectedModel) {
        setSelectedModel(status.models[0]);
      }
    } catch (err) {
      console.error('Failed to query Ollama status:', err);
    } finally {
      setStatusLoading(false);
    }
  };

  const handleExplain = async () => {
    const vuln = vulnerabilities.find((v) => v.id === selectedVulnId);
    if (!vuln) return;
    setLoading(true);
    setAiExplainResponse('');
    try {
      const res = await apiService.explainVulnerabilityAI({
        title: vuln.title,
        category: vuln.category,
        severity: vuln.severity,
        cwe: vuln.cwe,
        description: vuln.description,
        evidence: vuln.evidence_json,
        model: selectedModel,
      });
      if (res.success && res.response) {
        setAiExplainResponse(res.response);
      } else {
        setAiExplainResponse(`[Error del asistente local]: ${res.error || 'No se recibió respuesta válida'}`);
      }
    } catch (err) {
      setAiExplainResponse(`[Error de conexión]: ${String(err)}`);
    } finally {
      setLoading(false);
    }
  };

  const handlePrioritize = async () => {
    if (vulnerabilities.length === 0) return;
    setLoading(true);
    setAiPrioritizeResponse('');
    try {
      const res = await apiService.prioritizeVulnerabilitiesAI(
        JSON.stringify(vulnerabilities),
        selectedModel
      );
      if (res.success && res.response) {
        setAiPrioritizeResponse(res.response);
      } else {
        setAiPrioritizeResponse(`[Error del asistente local]: ${res.error || 'No se recibió respuesta'}`);
      }
    } catch (err) {
      setAiPrioritizeResponse(`[Error de conexión]: ${String(err)}`);
    } finally {
      setLoading(false);
    }
  };

  const handleCodeReview = async () => {
    if (!insecureCode.trim()) return;
    setLoading(true);
    setCodeReviewResponse('');
    try {
      const res = await apiService.explainVulnerabilityAI({
        title: 'Auditoría de Fragmento de Código Inseguro',
        category: 'Code Review',
        severity: 'high',
        cwe: 'CWE-89/CWE-79',
        description: 'Revisión estática de código para identificar vectores de inyección o sanitización ausente.',
        evidence: insecureCode,
        model: selectedModel,
      });
      if (res.success && res.response) {
        setCodeReviewResponse(res.response);
      } else {
        setCodeReviewResponse(`[Error]: ${res.error || 'Fallo al procesar código'}`);
      }
    } catch (err) {
      setCodeReviewResponse(`[Error]: ${String(err)}`);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="p-6 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Header and Ollama Status */}
      <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <BrainCircuit size={18} className="text-cyan-400" />
            Asistente de Ciberseguridad con IA Local (Ollama)
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Asistencia analítica 100% aislada (Air-Gapped). Explicación de vulnerabilidades y remediaciones sin enviar datos al exterior.
          </p>
        </div>

        {/* Local daemon status pill */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#0d121f] border border-[#1f293d] text-xs">
            <span
              className={`w-2 h-2 rounded-full ${
                ollamaStatus.available ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'
              }`}
            />
            <span className="text-slate-300 font-mono">
              {ollamaStatus.available
                ? `Ollama Conectado (${ollamaStatus.models.length} modelos)`
                : 'Ollama Offline'}
            </span>
            <button
              onClick={checkStatus}
              className="text-slate-400 hover:text-white ml-1"
              title="Reverificar estado"
            >
              <RotateCcw size={12} className={statusLoading ? 'animate-spin' : ''} />
            </button>
          </div>

          {ollamaStatus.available && (
            <select
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              className="bg-[#0d121f] border border-[#1f293d] rounded-lg px-3 py-1.5 text-xs text-slate-200 outline-none font-mono focus:border-cyan-500/50"
            >
              {ollamaStatus.models.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          )}
        </div>
      </div>

      {/* Offline Warning Notice */}
      {!ollamaStatus.available && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-xs text-amber-200 space-y-1.5">
          <div className="flex items-center gap-2 font-bold text-amber-300">
            <AlertCircle size={16} />
            El Asistente de IA es Opcional y no es obligatorio para auditar
          </div>
          <p className="text-amber-200/80 leading-relaxed">
            La plataforma funciona de manera completa sin IA. Si deseas habilitar el asistente local, inicia el daemon en tu sistema:{' '}
            <code className="bg-black/40 px-2 py-0.5 rounded font-mono text-cyan-300">ollama serve</code> y descarga un modelo como{' '}
            <code className="bg-black/40 px-2 py-0.5 rounded font-mono text-cyan-300">ollama pull qwen2.5-coder:14b</code> o{' '}
            <code className="bg-black/40 px-2 py-0.5 rounded font-mono text-cyan-300">ollama pull llama3</code>.
          </p>
        </div>
      )}

      {/* Functionality Tabs */}
      <div className="flex bg-[#111726] p-1 rounded-xl border border-[#1f293d] w-fit">
        <button
          onClick={() => setActiveTab('explain')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            activeTab === 'explain'
              ? 'bg-cyan-500/20 text-cyan-300 font-bold'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Sparkles size={14} />
          Explicación y Mitigación de Hallazgos
        </button>
        <button
          onClick={() => setActiveTab('prioritize')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            activeTab === 'prioritize'
              ? 'bg-cyan-500/20 text-cyan-300 font-bold'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <ListOrdered size={14} />
          Priorización Estratégica
        </button>
        <button
          onClick={() => setActiveTab('code_review')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            activeTab === 'code_review'
              ? 'bg-cyan-500/20 text-cyan-300 font-bold'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Code2 size={14} />
          Auditoría de Código Inseguro
        </button>
      </div>

      {/* Tab 1: Explain Finding */}
      {activeTab === 'explain' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] space-y-3">
              <label className="text-xs font-bold uppercase tracking-wider text-slate-400 block">
                Selecciona un hallazgo detectado:
              </label>
              <select
                value={selectedVulnId}
                onChange={(e) => setSelectedVulnId(e.target.value)}
                className="w-full bg-[#0d121f] border border-[#1f293d] rounded-lg p-2 text-xs text-slate-200 outline-none"
              >
                {vulnerabilities.map((v) => (
                  <option key={v.id} value={v.id}>
                    [{v.severity.toUpperCase()}] {v.title}
                  </option>
                ))}
              </select>

              <button
                onClick={handleExplain}
                disabled={loading || !ollamaStatus.available}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-bold text-xs shadow-md shadow-cyan-950 transition-all disabled:opacity-50"
              >
                <Sparkles size={14} />
                {loading ? 'Generando análisis...' : 'Explicar con IA Local'}
              </button>
            </div>
          </div>

          <div className="lg:col-span-2">
            <div className="p-5 rounded-xl bg-[#0d121f] border border-[#1f293d] min-h-[350px] space-y-3">
              <div className="flex items-center justify-between border-b border-[#1f293d] pb-2">
                <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5 font-mono">
                  <Bot size={15} className="text-cyan-400" />
                  RESPUESTA DEL MODELO: {selectedModel || 'NINGUNO'}
                </span>
                {aiExplainResponse && (
                  <button
                    onClick={() => handleCopy(aiExplainResponse)}
                    className="text-xs text-slate-400 hover:text-white flex items-center gap-1"
                  >
                    {copied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                    {copied ? 'Copiado' : 'Copiar'}
                  </button>
                )}
              </div>

              {loading ? (
                <div className="py-20 text-center text-xs text-slate-400 flex flex-col items-center gap-2">
                  <Cpu size={24} className="animate-spin text-cyan-400" />
                  <span>El modelo local está analizando el vector y formulando la remediación...</span>
                </div>
              ) : aiExplainResponse ? (
                <div className="prose prose-invert max-w-none text-xs text-slate-200 whitespace-pre-wrap font-sans leading-relaxed">
                  {aiExplainResponse}
                </div>
              ) : (
                <div className="py-20 text-center text-xs text-slate-400">
                  Selecciona un hallazgo y pulsa "Explicar con IA Local" para recibir una guía técnica de mitigación.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Prioritize */}
      {activeTab === 'prioritize' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] flex items-center justify-between">
            <div>
              <h4 className="text-xs font-bold text-slate-100">Matriz de Priorización de Riesgos</h4>
              <p className="text-xs text-slate-400">
                Evalúa los {vulnerabilities.length} hallazgos activos y genera un plan estructurado por urgencia.
              </p>
            </div>
            <button
              onClick={handlePrioritize}
              disabled={loading || !ollamaStatus.available || vulnerabilities.length === 0}
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-bold rounded-lg transition-colors disabled:opacity-50"
            >
              {loading ? 'Calculando prioridades...' : 'Generar Plan de Priorización'}
            </button>
          </div>

          <div className="p-5 rounded-xl bg-[#0d121f] border border-[#1f293d] min-h-[300px]">
            {loading ? (
              <div className="py-16 text-center text-xs text-slate-400 flex flex-col items-center gap-2">
                <Cpu size={24} className="animate-spin text-cyan-400" />
                <span>Analizando vectores de ataque y ordenando por criticidad...</span>
              </div>
            ) : aiPrioritizeResponse ? (
              <div className="prose prose-invert max-w-none text-xs text-slate-200 whitespace-pre-wrap font-sans leading-relaxed">
                {aiPrioritizeResponse}
              </div>
            ) : (
              <div className="py-16 text-center text-xs text-slate-400">
                Haz clic en "Generar Plan de Priorización" para obtener la hoja de ruta recomendada por el modelo local.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 3: Code Review */}
      {activeTab === 'code_review' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-3">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <Code2 size={14} className="text-cyan-400" />
              Fragmento de Código a Evaluar:
            </label>
            <textarea
              rows={12}
              value={insecureCode}
              onChange={(e) => setInsecureCode(e.target.value)}
              className="w-full bg-[#070a10] border border-[#1f293d] rounded-xl p-3 font-mono text-xs text-cyan-300 outline-none focus:border-cyan-500/50"
            />
            <button
              onClick={handleCodeReview}
              disabled={loading || !ollamaStatus.available}
              className="w-full py-2.5 bg-cyan-500 hover:bg-cyan-400 text-black font-bold text-xs rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center gap-1.5"
            >
              <Send size={14} />
              {loading ? 'Analizando sintaxis y flujo...' : 'Analizar y Refactorizar Código'}
            </button>
          </div>

          <div className="p-5 rounded-xl bg-[#0d121f] border border-[#1f293d] min-h-[300px] space-y-2">
            <span className="text-xs font-bold font-mono text-slate-400 block border-b border-[#1f293d] pb-2">
              RECOMENDACIÓN DE CODIFICACIÓN SEGURA
            </span>
            {loading ? (
              <div className="py-20 text-center text-xs text-slate-400 flex flex-col items-center gap-2">
                <Cpu size={24} className="animate-spin text-cyan-400" />
                <span>Revisando código e identificando fallos de sanitización...</span>
              </div>
            ) : codeReviewResponse ? (
              <div className="prose prose-invert max-w-none text-xs text-slate-200 whitespace-pre-wrap font-sans leading-relaxed overflow-y-auto max-h-[380px]">
                {codeReviewResponse}
              </div>
            ) : (
              <div className="py-20 text-center text-xs text-slate-400">
                Pega cualquier fragmento de código inseguro para que el modelo local sugiera una alternativa defensiva.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

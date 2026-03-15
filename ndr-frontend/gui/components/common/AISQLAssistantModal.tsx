import React from 'react';
import { Bot, Download, Sparkles, X } from 'lucide-react';

const AISQLAssistantModal: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const openGuide = () => {
    window.open('/guides/pcapql_ai_sql_guide.pdf', '_blank', 'noopener,noreferrer');
  };

  return (
    <div className="fixed inset-0 z-[85] flex items-center justify-center bg-black/60">
      <div className="w-[900px] max-w-[94vw] max-h-[90vh] overflow-hidden bg-[#111113] border border-[#2a2a2f] rounded-2xl shadow-2xl flex flex-col">
        <div className="px-5 py-3 border-b border-[#2a2a2f] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Bot size={16} className="text-[#00D4AA]" />
            <div>
              <h2 className="text-sm font-bold text-white">AI SQL Assistant</h2>
              <p className="text-[11px] text-gray-400">Download schema guide, upload to ChatGPT, generate SQL, run in PCAPQL</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/5 text-gray-400 hover:text-white">
            <X size={16} />
          </button>
        </div>

        <div className="p-5 overflow-auto space-y-4">
          <div className="rounded-xl border border-[#2a2a2f] bg-[#0f1115] p-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 mb-2 inline-flex items-center gap-2">
              <Sparkles size={13} /> Workflow
            </h3>
            <ol className="list-decimal list-inside space-y-1 text-xs text-gray-200">
              <li>Download the schema guide file (PDF, SQL, or Markdown).</li>
              <li>Upload the file into ChatGPT or your AI assistant.</li>
              <li>Ask the AI to generate a DuckDB SQL query for your SOC use case.</li>
              <li>Copy the SQL into PCAPQL SQL Query page and run it.</li>
              <li>Review results, refine query, and rerun as needed.</li>
            </ol>
          </div>

          <div className="rounded-xl border border-[#2a2a2f] bg-[#0f1115] p-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 mb-3">Download Schema Guide</h3>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={openGuide}
                className="inline-flex items-center gap-2 text-xs px-3 py-2 rounded-lg border border-[#00D4AA55] text-[#00D4AA] hover:bg-[#00D4AA10] font-semibold"
              >
                <Download size={13} /> Download PDF Guide
              </button>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};

export default AISQLAssistantModal;

import React from 'react';
import { ExternalLink, Network, X } from 'lucide-react';

const NODE_STYLE =
  'rounded-lg border border-[#2f3137] bg-[#121419] px-3 py-2 text-[11px] text-gray-200 min-w-[130px] text-center';

const ARROW_STYLE = 'text-[#00D4AA] text-sm font-bold';

const HowItWorksModal: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-black/60">
      <div className="w-[960px] max-w-[94vw] max-h-[90vh] overflow-hidden bg-[#111113] border border-[#2a2a2f] rounded-2xl shadow-2xl flex flex-col">
        <div className="px-5 py-3 border-b border-[#2a2a2f] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Network size={16} className="text-[#00D4AA]" />
            <div>
              <h2 className="text-sm font-bold text-white">How It Works</h2>
              <p className="text-[11px] text-gray-400">PCAPQL architecture from capture to SOC analysis</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/5 text-gray-400 hover:text-white">
            <X size={16} />
          </button>
        </div>

        <div className="p-5 overflow-auto space-y-4">
          <p className="text-xs text-gray-200 leading-relaxed">
            Uploaded packet captures are parsed by Zeek in the background, normalized by the Go enrichment pipeline,
            and made SQL-ready for investigation through DuckDB and Python APIs in the frontend.
          </p>

          <div className="rounded-xl border border-[#2a2a2f] bg-[#0f1115] p-4">
            <div className="flex flex-wrap items-center gap-2">
              <div className={NODE_STYLE}>PCAP / PCAPNG Upload</div>
              <span className={ARROW_STYLE}>→</span>
              <div className={NODE_STYLE}>
                Zeek Network Security Monitor
                <a
                  href="https://zeek.org/"
                  target="_blank"
                  rel="noreferrer"
                  className="mt-1 inline-flex items-center gap-1 text-[10px] text-[#38bdf8] hover:text-[#7dd3fc]"
                >
                  zeek.org <ExternalLink size={10} />
                </a>
              </div>
              <span className={ARROW_STYLE}>→</span>
              <div className={NODE_STYLE}>Zeek Kafka Plugin</div>
              <span className={ARROW_STYLE}>→</span>
              <div className={NODE_STYLE}>Kafka</div>
              <span className={ARROW_STYLE}>→</span>
              <div className={NODE_STYLE}>Golang Enrichment Pipeline</div>
              <span className={ARROW_STYLE}>→</span>
              <div className={NODE_STYLE}>Real-time Split Write</div>
              <span className={ARROW_STYLE}>→</span>
              <div className={NODE_STYLE}>Parquet Tables</div>
              <span className={ARROW_STYLE}>→</span>
              <div className={NODE_STYLE}>DuckDB + Python SQL/Scoring</div>
              <span className={ARROW_STYLE}>→</span>
              <div className={NODE_STYLE}>Frontend (Dashboard / Search / SQL Hunt)</div>
            </div>
          </div>

          <div className="rounded-xl border border-[#2a2a2f] bg-[#0f1115] p-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 mb-2">Flow Summary</h3>
            <ol className="list-decimal list-inside space-y-1 text-xs text-gray-300">
              <li>PCAP is uploaded and parsed by Zeek in the background.</li>
              <li>Zeek events are streamed through Kafka.</li>
              <li>Golang pipeline normalizes events and enriches fields in real time.</li>
              <li>Pipeline writes structured Parquet protocol tables.</li>
              <li>DuckDB + Python services run SQL and scoring for SOC workflows.</li>
              <li>Frontend presents dashboards, log search, and threat hunting views.</li>
            </ol>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HowItWorksModal;

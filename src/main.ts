import './styles.css';
import { renderBreakIt } from './ui/breakit';
import { renderModes } from './ui/modes';
import { renderNoncePanel } from './ui/nonce';
import { renderPipeline } from './ui/pipeline';
import { renderSigncryption } from './ui/signcryption';
import { renderIntro, renderNonGoals, renderPqPanel, renderScopeStrip } from './ui/statics';
import { LabStore } from './ui/state';

const app = document.getElementById('app');
if (!app) throw new Error('missing #app mount');

const store = new LabStore();

const main = document.createElement('main');
main.className = 'lab-main';
main.append(
  renderIntro(),
  renderPipeline(store),
  renderModes(store),
  renderNoncePanel(store),
  renderBreakIt(store),
  renderSigncryption(),
  renderNonGoals(),
  renderPqPanel(),
  renderScopeStrip(),
);
app.append(main);

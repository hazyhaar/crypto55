/**
 * crypto55 — Bac à sable interactif OneStep & Simulation EVM
 * Script client autonome, pur JS standard sans dépendance.
 */

document.addEventListener('DOMContentLoaded', () => {
  const btnExecute = document.getElementById('btnExecute');
  const opSelect = document.getElementById('opSelect');
  const stackInput0 = document.getElementById('stackInput0');
  const stackInput1 = document.getElementById('stackInput1');
  const gasLimit = document.getElementById('gasLimit');
  const tamperCheck = document.getElementById('tamperCheck');

  const statusIndicator = document.getElementById('statusIndicator');
  const statusMessage = document.getElementById('statusMessage');
  const outGas = document.getElementById('outGas');
  const outPC = document.getElementById('outPC');
  const outStack = document.getElementById('outStack');
  const outPreRoot = document.getElementById('outPreRoot');
  const outPostRoot = document.getElementById('outPostRoot');
  const outABI = document.getElementById('outABI');

  // Ajuste les champs de pile selon l'opcode sélectionné
  opSelect.addEventListener('change', () => {
    const op = opSelect.value;
    if (op === 'PUSH1') {
      stackInput0.parentElement.querySelector('label').textContent = 'Valeur immédiate à empiler :';
      stackInput1.parentElement.style.display = 'none';
    } else if (op === 'DUP1' || op === 'SWAP1') {
      stackInput0.parentElement.querySelector('label').textContent = 'Sommet de pile [0] :';
      stackInput1.parentElement.style.display = 'block';
      stackInput1.parentElement.querySelector('label').textContent = 'Élément de pile [1] :';
    } else {
      stackInput0.parentElement.querySelector('label').textContent = 'Sommet de pile [0] (opérande 1) :';
      stackInput1.parentElement.style.display = 'block';
      stackInput1.parentElement.querySelector('label').textContent = 'Élément de pile [1] (opérande 2) :';
    }
  });

  // Exécution de la simulation
  btnExecute.addEventListener('click', async () => {
    btnExecute.disabled = true;
    statusIndicator.className = 'status-indicator running';
    statusIndicator.textContent = 'En cours...';
    statusMessage.textContent = 'Exécution du micro-noyau crypto55 c2evm...';

    const op = opSelect.value;
    const s0 = stackInput0.value.trim();
    const s1 = stackInput1.value.trim();
    const gas = parseInt(gasLimit.value, 10) || 100000;
    const tamper = tamperCheck.checked;

    const stack = [];
    if (op === 'PUSH1') {
      stack.push(s0);
    } else {
      stack.push(s0);
      if (stackInput1.parentElement.style.display !== 'none') {
        stack.push(s1);
      }
    }

    const payload = {
      opcode: op,
      stack: stack,
      pc: 0,
      gas: gas,
      tamper: tamper
    };

    try {
      const resp = await fetch('/api/simulate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      let data = {};
      try {
        data = await resp.json();
      } catch (jsonErr) {
        data = { error: 'Réponse serveur invalide (' + resp.status + ')' };
      }

      if (!resp.ok || !data.success) {
        statusIndicator.className = 'status-indicator dispute-alert';
        statusIndicator.textContent = 'Erreur EVM (' + resp.status + ')';
        statusMessage.textContent = data.error || 'Échec de la transition EVM.';
        outStack.textContent = '—';
        outPreRoot.textContent = data.pre_state_root || '—';
        outPostRoot.textContent = data.post_state_root || '—';
        outABI.textContent = data.witness_abi || '—';
        return;
      }

      // Mise à jour de l'affichage
      if (tamper) {
        statusIndicator.className = 'status-indicator dispute-alert';
        statusIndicator.textContent = 'Litige Détecté !';
        statusMessage.textContent = 'Preuve OneStep validée : la racine post-état frauduleuse a été rejetée par le vérificateur L1 !';
      } else {
        statusIndicator.className = 'status-indicator success';
        statusIndicator.textContent = 'Validé (0 Litige)';
        statusMessage.textContent = `Transition réussie en 0 allocation. Témoin OneStep vérifié avec succès.`;
      }

      outGas.textContent = `${data.gas_out} (${data.gas_used} gaz consommé)`;
      outPC.textContent = `PC: ${data.pc_in} → ${data.pc_out}`;

      if (data.stack_out && data.stack_out.length > 0) {
        outStack.textContent = data.stack_out.join('\n');
      } else {
        outStack.textContent = '(pile vide)';
      }

      outPreRoot.textContent = data.pre_state_root;
      outPostRoot.textContent = data.post_state_root;
      outABI.textContent = data.witness_abi;

    } catch (err) {
      statusIndicator.className = 'status-indicator dispute-alert';
      statusIndicator.textContent = 'Erreur Réseau';
      statusMessage.textContent = `Impossible de contacter le serveur d'évaluation : ${err.message}`;
    } finally {
      btnExecute.disabled = false;
    }
  });

  // Déclenche une simulation initiale à l'ouverture
  btnExecute.click();
});

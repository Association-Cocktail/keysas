<!--
  Composant de progression KeySAS
  À ajouter dans keysas-frontend/src/components/
-->
<template>
  <div class="keysas-progress">
    <!-- Progression keysas-in -->
    <div v-if="progressIn" class="progress-section">
      <h3>📥 Réception des fichiers</h3>
      <div class="progress-overview">
        <span class="badge">{{ progressIn.processed_files }}/{{ progressIn.total_files }}</span>
        <span v-if="progressIn.current_file" class="current-step">
          {{ progressIn.current_file.step_description }}
        </span>
      </div>

      <!-- Fichier actuel -->
      <div v-if="progressIn.current_file" class="current-file">
        <div class="file-info">
          <span class="filename">📄 {{ progressIn.current_file.filename }}</span>
          <span class="percentage">{{ progressIn.current_file.percentage }}%</span>
        </div>
        <div class="progress-bar">
          <div
            class="progress-fill"
            :style="{ width: progressIn.current_file.percentage + '%' }"
          ></div>
        </div>
      </div>

      <!-- File d'attente -->
      <div v-if="progressIn.queue.length > 0" class="queue-info">
        <small>📋 En attente: {{ progressIn.queue.length }} fichier(s)</small>
      </div>
    </div>

    <!-- Progression keysas-transit -->
    <div v-if="progressTransit" class="progress-section analysis">
      <h3>🔍 Analyse en cours</h3>
      <div class="progress-overview">
        <span class="badge">{{ progressTransit.processed_files }}/{{ progressTransit.total_files }}</span>
        <span v-if="progressTransit.current_file" class="current-step">
          {{ progressTransit.current_file.step_description }}
        </span>
      </div>

      <!-- Fichier actuel avec progression détaillée -->
      <div v-if="progressTransit.current_file" class="current-file">
        <div class="file-info">
          <span class="filename">📄 {{ progressTransit.current_file.filename }}</span>
          <span class="percentage">{{ progressTransit.current_file.percentage }}%</span>
        </div>
        <div class="progress-bar">
          <div
            class="progress-fill analysis"
            :style="{ width: progressTransit.current_file.percentage + '%' }"
          ></div>
        </div>

        <!-- Étapes d'analyse -->
        <div class="analysis-steps">
          <div
            v-for="step in analysisSteps"
            :key="step.key"
            :class="['step', { active: progressTransit.current_file.step === step.key, completed: getStepPercentage(step.key) < progressTransit.current_file.percentage }]"
          >
            <span class="step-icon">{{ step.icon }}</span>
            <span class="step-label">{{ step.label }}</span>
          </div>
        </div>
      </div>

      <!-- Statistiques -->
      <div class="stats">
        <span class="stat success">✅ {{ progressTransit.processed_files }} réussis</span>
        <span v-if="progressTransit.failed_files > 0" class="stat error">❌ {{ progressTransit.failed_files }} échoués</span>
      </div>
    </div>

    <!-- Aucune progression -->
    <div v-if="!progressIn && !progressTransit" class="no-progress">
      <p>🎯 En attente de fichiers...</p>
    </div>
  </div>
</template>

<script>
export default {
  name: 'KeysasProgress',
  props: {
    status: {
      type: Object,
      required: true
    }
  },
  data() {
    return {
      analysisSteps: [
        { key: 'Pending', icon: '⏳', label: 'En attente' },
        { key: 'Hashing', icon: '🔐', label: 'Hash SHA256' },
        { key: 'CheckingSize', icon: '📏', label: 'Taille' },
        { key: 'CheckingFileType', icon: '📄', label: 'Type de fichier' },
        { key: 'AntivirusScan', icon: '🦠', label: 'Antivirus' },
        { key: 'YaraScan', icon: '🔍', label: 'YARA' },
        { key: 'VerifyingSignature', icon: '✍️', label: 'Signature' },
        { key: 'Complete', icon: '✅', label: 'Terminé' }
      ]
    };
  },
  computed: {
    progressIn() {
      return this.status.progress_in;
    },
    progressTransit() {
      return this.status.progress_transit;
    }
  },
  methods: {
    getStepPercentage(step) {
      const percentages = {
        'Pending': 0,
        'Hashing': 10,
        'CheckingSize': 20,
        'CheckingFileType': 30,
        'AntivirusScan': 50,
        'YaraScan': 75,
        'VerifyingSignature': 90,
        'Complete': 100
      };
      return percentages[step] || 0;
    }
  }
};
</script>

<style scoped>
.keysas-progress {
  padding: 20px;
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

.progress-section {
  background: #f8f9fa;
  border-radius: 8px;
  padding: 15px;
  margin-bottom: 15px;
  border-left: 4px solid #007bff;
}

.progress-section.analysis {
  border-left-color: #28a745;
}

.progress-overview {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 15px;
}

.badge {
  background: #007bff;
  color: white;
  padding: 5px 12px;
  border-radius: 20px;
  font-size: 14px;
  font-weight: bold;
}

.current-step {
  color: #6c757d;
  font-size: 14px;
}

.current-file {
  background: white;
  border-radius: 6px;
  padding: 12px;
  margin-bottom: 10px;
}

.file-info {
  display: flex;
  justify-content: space-between;
  margin-bottom: 8px;
}

.filename {
  font-weight: 500;
  color: #333;
}

.percentage {
  font-weight: bold;
  color: #007bff;
}

.progress-bar {
  background: #e9ecef;
  border-radius: 10px;
  height: 20px;
  overflow: hidden;
  position: relative;
}

.progress-fill {
  background: linear-gradient(90deg, #007bff, #0056b3);
  height: 100%;
  transition: width 0.3s ease;
  border-radius: 10px;
}

.progress-fill.analysis {
  background: linear-gradient(90deg, #28a745, #1e7e34);
}

.analysis-steps {
  display: flex;
  justify-content: space-between;
  margin-top: 12px;
  padding: 0 5px;
}

.step {
  display: flex;
  flex-direction: column;
  align-items: center;
  font-size: 12px;
  color: #6c757d;
  opacity: 0.5;
  transition: all 0.3s ease;
}

.step.active {
  opacity: 1;
  color: #007bff;
  font-weight: bold;
  transform: scale(1.1);
}

.step.completed {
  opacity: 1;
  color: #28a745;
}

.step-icon {
  font-size: 20px;
  margin-bottom: 4px;
}

.step-label {
  font-size: 10px;
  text-align: center;
}

.queue-info {
  text-align: center;
  color: #6c757d;
  font-size: 12px;
}

.stats {
  display: flex;
  gap: 15px;
  margin-top: 10px;
}

.stat {
  font-size: 13px;
  padding: 5px 10px;
  border-radius: 4px;
}

.stat.success {
  background: #d4edda;
  color: #155724;
}

.stat.error {
  background: #f8d7da;
  color: #721c24;
}

.no-progress {
  text-align: center;
  color: #6c757d;
  padding: 40px;
  font-size: 16px;
}

h3 {
  margin: 0 0 15px 0;
  font-size: 18px;
  color: #333;
}
</style>

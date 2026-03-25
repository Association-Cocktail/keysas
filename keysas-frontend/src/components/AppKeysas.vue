<template>
    <h2>
      {{ $t('guichet_'+type+'.is_'+(this.working ? 'working' : 'ready')) }}
    </h2>

    <!-- USB Key list -->
    <div :class="'AppGuichet-item AppGuichet-item-' + (this.usb.length > 0 ? 'active' : 'inactive') + ' AppGuichet-device AppGuichet-device-'+this.type">
      <div class="AppGuichet-item-head">
        <span class="check-icon" />
        <p>
          {{ $t('guichet_'+type+'.usb_device.'+(this.usb.length > 0 ? 'connected' : 'not_found')) }}
        </p>
      </div>
      <ul v-if="this.usb.length > 0">
        <li v-for="(device, index) in this.usb" v-bind:key="index"> {{ device }}</li>
      </ul>
    </div>

    <!-- Status Guichet IN -->
    <div v-if="this.type === 'IN'">
      <div v-if="this.working" class="AppGuichet-item AppGuichet-item-working AppGuichet-files">
        <div class="AppGuichet-item-head">
          <span class="working-icon" />
          <p>{{ $t('guichet_IN.tasks.analysing_files') }}</p>
        </div>

        <!-- Progress bars -->
        <div v-if="progressIN || progressTRANSIT" class="AppGuichet-progress">

          <!-- keysas-in: réception -->
          <div v-if="progressIN && progressIN.total_files > 0" class="progress-section">
            <div class="progress-label">
              <span>Réception</span>
              <span>{{ progressIN.processed_files + progressIN.failed_files }}/{{ progressIN.total_files }} fichiers</span>
            </div>
            <div class="progress">
              <div class="progress-bar progress-bar-in"
                   role="progressbar"
                   :style="{ width: overallInPercent + '%' }">
              </div>
            </div>
          </div>

          <!-- keysas-transit: fichier en cours -->
          <div v-if="progressTRANSIT && progressTRANSIT.current_file" class="progress-section">
            <div class="progress-label">
              <span class="progress-filename">{{ progressTRANSIT.current_file.filename }}</span>
              <span>{{ progressTRANSIT.current_file.percentage }}%</span>
            </div>
            <div class="progress-step">{{ $t(progressTRANSIT.current_file.step_description, progressTRANSIT.current_file.step_description) }}</div>
            <div class="progress">
              <div class="progress-bar progress-bar-transit"
                   role="progressbar"
                   :style="{ width: progressTRANSIT.current_file.percentage + '%' }">
              </div>
            </div>
          </div>

          <!-- keysas-transit: progression globale -->
          <div v-if="progressTRANSIT && progressTRANSIT.total_files > 0" class="progress-section">
            <div class="progress-label">
              <span>Analyse</span>
              <span>{{ progressTRANSIT.processed_files + progressTRANSIT.failed_files }}/{{ progressTRANSIT.total_files }} fichiers</span>
            </div>
            <div class="progress">
              <div class="progress-bar progress-bar-transit"
                   role="progressbar"
                   :style="{ width: overallTransitPercent + '%' }">
              </div>
            </div>
          </div>

        </div>
      </div>
      <div v-else-if="this.listInBackup.length === 0" class="AppGuichet-item AppGuichet-item-inactive AppGuichet-files">
        <div class="AppGuichet-item-head">
          <p>{{ $t('guichet_IN.files.not_found') }}</p>
        </div>
      </div>
      <div v-else class="AppGuichet-item AppGuichet-item-active AppGuichet-files">
        <div class="AppGuichet-item-head">
          <span class="check-icon" />
          <p>
            {{ $tc('guichet_IN.files.x_files_analysed', this.listInBackup.length) }}
          </p>
        </div>
      </div>
    </div>

    <!-- Status Guichet OUT -->
    <div v-if="this.type === 'OUT'">
      <div v-if="this.files.length === 0" class="AppGuichet-item AppGuichet-item-inactive AppGuichet-files">
        <div class="AppGuichet-item-head">
          <p>{{ $t('guichet_OUT.files.not_found') }}</p>
        </div>
      </div>
      <div v-else-if="this.usb.length > 0" class="AppGuichet-item AppGuichet-item-working AppGuichet-files">
        <div class="AppGuichet-item-head">
          <span class="working-icon" />
          <p >{{ $t('guichet_OUT.tasks.transferring_files') }}</p>
        </div>
      </div>
      <div v-else class="AppGuichet-item AppGuichet-item-active AppGuichet-files">
        <div class="AppGuichet-item-head">
          <span class="check-icon" />
          <p>
            {{ $tc('guichet_OUT.files.x_files_ready_for_transfer', this.listOutOK.length) }}
          </p>
        </div>
      </div>
    </div>

    <!-- List Detail visibility switchers -->
    <h5 v-if="this.type === 'IN' && this.listInBackup.length > 0" class="AppGuichet-switcher">
      <a @click="this.displayDetail = !this.displayDetail" :class="this.displayDetail ? 'AppGuichet-switcher-active' : null">
        {{ $t('guichet_IN.files.list.'+(this.displayDetail ? 'hide' : 'show')) }}
      </a>
    </h5>
    <h5 v-else-if="this.type === 'OUT' && (this.listOutOK.length > 0 || this.listOutError.length > 0)" class="AppGuichet-switcher">
      <a @click="this.displayErrors = false; this.activeDetail = null" :class="(this.displayErrors ? null : 'AppGuichet-switcher-active') + ' AppGuichet-switcher-first'">
        {{ $tc('guichet_OUT.files.x_files_verified_available', this.listOutOK.length) }}
      </a>
      <a v-if="this.listOutError.length > 0" @click="this.displayErrors = true; this.activeDetail = null" :class="this.displayErrors ? 'AppGuichet-switcher-active' : null">
        {{ $tc('guichet_OUT.files.x_files_refused', this.listOutError.length) }}
      </a>
    </h5>

    <!-- List Detail -->
    <ul v-if="this.type === 'IN' && this.listInBackup.length > 0 && this.displayDetail" class="AppGuichet-list list-group">
      <li class="list-group-item list-in" v-for="(file, index) in this.listInBackup" v-bind:key="index">{{ file.filename }}<span class="file-error">{{ file.error ? $t(file.error) : '' }}</span></li>
    </ul>
    <ul v-if="this.type === 'OUT' && this.listOutOK.length > 0 && !this.displayErrors" class="AppGuichet-list list-group">
      <li class="list-group-item list-out list-out-expandable" v-for="(file, index) in this.listOutOK" v-bind:key="index">
        <div class="file-row">
          <span class="file-name">{{ file.filename }}</span>
          <span v-if="file.checks" class="file-checks">
            <span
              v-for="[key, pass] in sortedChecks(file.checks)"
              :key="key"
              class="check-badge"
              :class="[pass ? 'check-badge-ok' : 'check-badge-ko', isActiveDetail('ok', index, key) ? 'check-badge-active' : '']"
              :title="$t('header.checks.' + key)"
              @click="!pass && toggleDetail('ok', index, key)"
            >{{ checkIcon(key) }}</span>
          </span>
        </div>
        <div v-if="isActiveDetail('ok', index, null)" class="check-detail-panel">
          <span class="check-detail-label">{{ $t('header.checks.' + activeDetail.key) }}</span>
          <span class="check-detail-text">{{ (file.check_details && file.check_details[activeDetail.key]) || '—' }}</span>
        </div>
      </li>
    </ul>
    <ul v-if="this.type === 'OUT' && this.listOutError.length > 0 && this.displayErrors" class="AppGuichet-list list-group">
      <li class="list-group-item list-out-error list-out-expandable" v-for="(file, index) in this.listOutError" v-bind:key="index">
        <div class="file-row">
          <span class="file-name">{{ file.filename }}</span>
          <span v-if="file.checks" class="file-checks">
            <span
              v-for="[key, pass] in sortedChecks(file.checks)"
              :key="key"
              class="check-badge"
              :class="[pass ? 'check-badge-ok' : 'check-badge-ko', isActiveDetail('error', index, key) ? 'check-badge-active' : '']"
              :title="$t('checks.' + key)"
              @click="!pass && toggleDetail('error', index, key)"
            >{{ checkIcon(key) }}</span>
          </span>
        </div>
        <div v-if="isActiveDetail('error', index, null)" class="check-detail-panel">
          <span class="check-detail-label">{{ $t('header.checks.' + activeDetail.key) }}</span>
          <span class="check-detail-text">{{ (file.check_details && file.check_details[activeDetail.key]) || '—' }}</span>
        </div>
      </li>
    </ul>

    <!-- USB IN Help placeholder -->
    <div v-if="this.type === 'IN' && this.usb.length === 0 && this.listInBackup.length === 0" class="AppGuichet-plugMessage">
      <p>{{ $t('guichet_IN.usb_device.insert_placeholder') }}</p>
      <img src="../assets/img/big-top-arrow.png" />
    </div>
</template>

<script>
export default {
  name: "AppKeysas",
  props: [
    "type",
    "working",
    "usb",
    "files",
    "progressIN",
    "progressTRANSIT",
  ],
  computed: {
    overallInPercent() {
      if (!this.progressIN || this.progressIN.total_files === 0) return 0;
      return Math.round((this.progressIN.processed_files + this.progressIN.failed_files) / this.progressIN.total_files * 100);
    },
    overallTransitPercent() {
      if (!this.progressTRANSIT || this.progressTRANSIT.total_files === 0) return 0;
      return Math.round((this.progressTRANSIT.processed_files + this.progressTRANSIT.failed_files) / this.progressTRANSIT.total_files * 100);
    },
  },
  data() {
    return {
      displayDetail: false,
      displayErrors: false,
      listInBackup: [],
      listOutOK: [],
      listOutError: [],
      activeDetail: null, // { list: 'ok'|'error', idx: number, key: string }
    }
  },
  emits: ['guichetInCleared', 'guichetOutCleared'],
  methods: {
    clearAllLists() {
      this.listInBackup = [];
      this.listOutOK = [];
      this.listOutError = [];
      return;
    },
    clearListIn() {
      this.listInBackup = [];
      return;
    },
    checkIcon(key) {
      const icons = { hash: '#', size: '⊙', type: 'T', av: '☣', yara: '🏷', specialized: '🛡', vt: '☢' };
      return icons[key] || key.charAt(0).toUpperCase();
    },
    sortedChecks(checks) {
      const order = ['hash', 'size', 'type', 'av', 'yara', 'specialized', 'vt'];
      if (!checks) return [];
      return order.filter(k => k in checks).map(k => [k, checks[k]]);
    },
    toggleDetail(list, idx, key) {
      if (this.activeDetail && this.activeDetail.list === list && this.activeDetail.idx === idx && this.activeDetail.key === key) {
        this.activeDetail = null;
      } else {
        this.activeDetail = { list, idx, key };
      }
    },
    isActiveDetail(list, idx, key) {
      if (!this.activeDetail) return false;
      if (this.activeDetail.list !== list || this.activeDetail.idx !== idx) return false;
      return key === null || this.activeDetail.key === key;
    },
  },
  watch: {
    files(val, oldVal) {
      if(this.type === 'IN') {
        if(val.length === 0 && oldVal.length > 0) {
          setTimeout(() => {
            this.$emit('guichetInCleared');
          }, 5000);
          return;
        }

        val.forEach(element => {
          if(!this.listInBackup.map(x => x.filename).includes(element.filename)) {
            this.listInBackup.push({
              filename: element.filename,
              error: element.is_valid ? null : ('guichet_OUT.files.error.reason.' + (element.reason || 'unknown'))
            });
          }
        });
        return;
      }

      if(this.type === 'OUT') {
        if(val.length === 0 && oldVal.length > 0) {
          this.$emit('guichetOutCleared');
          return;
        }

        val.forEach(element => {
          if(element.is_valid) {
            if(!this.listOutOK.map(x => x.filename).includes(element.filename)) {
              this.listOutOK.push({
                filename: element.filename,
                reason: null,
                detail: null,
                checks: element.checks || null,
                check_details: element.check_details || null,
              });
            }
          } else {
            if(!this.listOutError.map(x => x.filename).includes(element.filename)) {
              this.listOutError.push({
                filename: element.filename,
                reason: element.reason || 'unknown',
                detail: element.detail || null,
                checks: element.checks || null,
                check_details: element.check_details || null,
              });
            }
          }
        });
      }
    },
  }
}
</script>

<style lang="scss">
@import "../assets/style/app.scss";

.AppGuichet-item {
	padding: 20px;
	margin-top: 15px;
	border-radius: 5px;
	@include media-breakpoint-down(lg) {
		padding: 11px;
		margin-top: 10px;
	}

.AppGuichet-item-head {
	display: flex;
	align-items: center;
	justify-content: flex-start;

	& > .working-icon,
	& > .check-icon {
		margin-right: 13px;
		display: inline-block;
		min-width: 32px;
		min-height: 32px;
		flex-basis: 32px;
		background-color: white;
		border-radius: 16px;
		background-repeat: no-repeat;
		background-position: center;
	}
	& > .working-icon {
		background-image: url("../assets/img/hourglass.svg");
	}
	& > .check-icon {
		display: none;
		background-image: url("../assets/img/check.svg");
	}
}

& > p {
	display: inline-block;
	vertical-align: top;
	line-height: 1rem;
}

&-active {
	color: $status-ok;
	background-color: $status-bg-ok;
	ul {
		color: $status-ok-light;
	}
	.AppGuichet-item-head > .check-icon {
		display: inline-block;
	}
}
  &-working {
  	color: $status-working;
  	background-color: $status-bg-working;
  }
  &-inactive {
  	color: $status-off;
  	background-color: $status-bg-off;
  }

  p {
  	margin: 0;
  	font-size: 0.85rem;
  }
  ul {
  	font-size: 0.8rem;
  	list-style-type: none;
  	padding-top: 0.5rem;
  	padding-left: 0;
  	margin-bottom: 0;
  }
}

.AppGuichet-device {
	position: relative;
	overflow: hidden;

	&:before {
		content: " ";
		position: absolute;
		top: 0;
		left: 0;
		height: 100%;
		width: 100%;
		opacity: 0.15;
		background-repeat: no-repeat;
	}

	&-IN:before {
		background-position: 93% 110%;
		background-size: 25px auto;
		background-image: url("../assets/img/usbkey.svg");
		@include media-breakpoint-down(lg) {
			background-size: 20px auto;
		}
	}

	&-OUT:before {
		background-position: 95% 110%;
		background-size: 32px auto;
		background-image: url("../assets/img/usbkey-signed.svg");
		@include media-breakpoint-down(lg) {
			background-size: 25px auto;
		}
	}

	ul {
		margin-left: 45px;
		margin-top: -10px;
	}
}

.AppGuichet-files {
	position: relative;
	overflow: hidden;

	&:before {
		content: " ";
		position: absolute;
		top: 0;
		left: 0;
		height: 100%;
		width: 100%;
		opacity: 0.15;
		background-repeat: no-repeat;
		background-position: 95% 120%;
		background-size: 36px auto;
		background-image: url("../assets/img/document.svg");
		@include media-breakpoint-down(lg) {
			background-size: 25px auto;
		}
	}
}

.AppGuichet-switcher {
	margin: 18px 0 6px;
	@include media-breakpoint-down(lg) {
		margin: 10px 0 6px;
	}
	a {
		padding: 0 0 0 15px;
		font-weight: 400;
		color: $grey-medium;
		&:first-of-type {
			padding: 0 15px 0 0;
		}
		&.AppGuichet-switcher-first {
			border-right: 1px solid $grey-medium;
		}
		&.AppGuichet-switcher-active {
			font-weight: 700;
			color: $grey-dark;
		}
	}
}

.AppGuichet-list {
	margin-top: 10px;
	font-size: 0.75rem;
	overflow-y: scroll;
	max-height: 230px;
	border: 1px solid $grey-dark;
	@include media-breakpoint-down(lg) {
		max-height: 150px;
	}

	.list-out-error,
	.list-in,
	.list-out {
		.file-row {
			display: flex;
			justify-content: space-between;
			align-items: center;
			gap: 6px;
		}

		.file-name {
			overflow: hidden;
			text-overflow: ellipsis;
			white-space: nowrap;
			flex-shrink: 1;
			min-width: 0;
		}

		.file-checks {
			display: flex;
			gap: 3px;
			flex-shrink: 0;
		}

		.check-badge {
			display: inline-flex;
			align-items: center;
			justify-content: center;
			width: 16px;
			height: 16px;
			border-radius: 3px;
			font-size: 0.6rem;
			font-weight: 700;
			line-height: 1;
			color: white;
			cursor: default;
			user-select: none;
			transition: opacity 0.15s, outline 0.1s;

			&-ok  { background-color: #4caf50; }
			&-ko  { background-color: #e53935; cursor: pointer; &:hover { opacity: 0.8; } }
			&-active { outline: 2px solid rgba(255,255,255,0.8); outline-offset: 1px; }
		}

		.check-detail-panel {
			margin-top: 4px;
			padding: 4px 6px;
			border-radius: 3px;
			background-color: rgba(0,0,0,0.12);
			font-size: 0.7rem;
			word-break: break-word;

			.check-detail-label {
				font-weight: 700;
				margin-right: 4px;
			}
			.check-detail-text {
				opacity: 0.9;
			}
		}
	}

	.list-out-expandable {
		display: block;
	}
}

.AppGuichet-progress {
  margin-top: 14px;

  .progress-section {
    margin-bottom: 10px;

    &:last-child {
      margin-bottom: 0;
    }
  }

  .progress-label {
    display: flex;
    justify-content: space-between;
    font-size: 0.75rem;
    font-weight: 600;
    margin-bottom: 4px;
    opacity: 0.9;
  }

  .progress-filename {
    max-width: 70%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .progress-step {
    font-size: 0.7rem;
    opacity: 0.75;
    margin-bottom: 3px;
    font-style: italic;
  }

  .progress {
    height: 6px;
    border-radius: 3px;
    background-color: rgba(255, 255, 255, 0.35);
    overflow: hidden;
  }

  .progress-bar {
    height: 100%;
    border-radius: 3px;
    transition: width 0.4s ease;

    &-in {
      background-color: $white;
    }

    &-transit {
      background-color: $cyan;
    }
  }
}

.AppGuichet-plugMessage {
	text-align: center;
	p {
		color: $grey-medium;
		font-size: 1.1rem;
		margin: 30px auto;
	}
	@include media-breakpoint-down(lg) {
		img {
			height: 60px;
		}
		p {
			font-size: 0.9rem;
		}
	}
}


</style>

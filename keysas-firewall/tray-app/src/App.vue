<script setup lang="ts">
import 'bootstrap-icons/font/bootstrap-icons.css'
import {listen} from '@tauri-apps/api/event'
</script>

<template>
  <div class="app_container">
    <table>
      <thead>
        <tr>
          <th><span class="app_icon"></span></th>
          <th class="app_title">Keysas USB Firewall</th>
        </tr>
      </thead>
    </table>
    <!-- Settings view -->
    <div v-if="currentView === 'settings'" class="settings-view">
      <h3>Policy Settings</h3>
      <label class="setting-row">
        <input type="checkbox" v-model="policy.disable_unsigned_usb"/>
        Block USB devices without a Keysas certificate
      </label>
      <label class="setting-row">
        <input type="checkbox" v-model="policy.allow_user_usb_authorization"/>
        Allow users to authorize unrecognised USB devices
      </label>
      <label class="setting-row">
        <input type="checkbox" v-model="policy.allow_user_file_read"/>
        Allow users to grant read access to uncertified files
      </label>
      <label class="setting-row">
        <input type="checkbox" v-model="policy.allow_user_file_write"/>
        Allow users to grant write access to files
      </label>
      <div class="settings-actions">
        <button @click="saveSettings()">Apply</button>
        <button @click="currentView = 'home'">Cancel</button>
      </div>
      <div v-if="settingsError" class="settings-error">{{ settingsError }}</div>
    </div>
    <!-- Placeholder: shown when no device is selected from the tray menu -->
    <div v-if="currentView === 'home'" class="placeholder">
      Select a device from the system tray menu.
    </div>
    <!-- File details view -->
    <table v-if="currentView === 'device'">
      <thead>
        <tr>
          <th style="width:85%">{{ usb_device.name }}</th>
          <th>
            <button class="bi-arrow-left" @click="backToUsbList()"></button>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="file in file_list">
          <td>{{ file.path }}</td>
          <td v-if="file.authorization == AuthorizationMode.AllowRead">
            <button class="bi-file-earmark-check" @click="toggleFileAuth(file, AuthorizationMode.AllowRW)"></button>
          </td>
          <td v-if="file.authorization == AuthorizationMode.AllowRW">
            <button class="bi-file-earmark-plus" @click="toggleFileAuth(file, AuthorizationMode.Block)"></button>
          </td>
          <td v-if="file.authorization == AuthorizationMode.Block">
            <button class="bi-file-earmark-x" @click="toggleFileAuth(file, AuthorizationMode.AllowRead)"></button>
          </td>
        </tr>
      </tbody>
    </table>
    <!-- Back button shown in device or settings view -->
    <div v-if="currentView !== 'home'" style="margin-top:8px;text-align:right;padding-right:8px;">
    </div>
  </div>
</template>

<script lang="ts">
import {invoke} from "@tauri-apps/api/core"
import {getCurrentWebviewWindow} from '@tauri-apps/api/webviewWindow'

// Must match UsbAuthorization in service_if.rs
enum AuthorizationMode {
  Pending   = 0,
  Block     = 1,
  AllowRead = 2,
  AllowRW   = 3,
  AllowAll  = 4,
}

declare interface UsbDevice {
  id: string,
  name: string,
  path: string,
  authorization: number
}

declare interface File {
  device: string,
  id: number[],
  path: string,
  authorization: AuthorizationMode
}

export default {
  name: 'App',
  components: {},
  data() {
    return {
      currentView: 'home' as 'home' | 'device' | 'settings',
      file_list: [] as File[],
      usb_device: {} as UsbDevice,
      policy: { disable_unsigned_usb: false, allow_user_usb_authorization: false,
                 allow_user_file_read: false, allow_user_file_write: false },
      settingsError: '' as string,
    }
  },
  async mounted() {
    await listen('show_device', (event) => {
      this.showUsbDevice(event.payload as UsbDevice);
    });
    await listen('file_update', (event) => {
      this.refreshFileList(event.payload as string);
    });
    await listen('show_settings', () => {
      this.openSettings();
    });
  },
  methods: {
    async refreshFileList(device_path: string) {
      if (device_path === this.usb_device.path) {
        invoke('get_file_list', {devicePath: device_path})
          .then((result) => {
            const file_list = JSON.parse(result as string);
            file_list.forEach((file: File) => {
              if (!this.file_list.some(f => f.path === file.path)) {
                this.file_list.push(file);
              }
            });
          })
          .catch((error) => console.error(error));
      }
    },
    async showUsbDevice(usb_device: UsbDevice) {
      this.usb_device = usb_device;
      this.file_list = [];
      this.refreshFileList(usb_device.path);
      this.currentView = 'device';
    },
    async openSettings() {
      this.settingsError = '';
      try {
        const raw = await invoke('get_policy_settings') as string;
        this.policy = JSON.parse(raw);
      } catch (e) {
        this.settingsError = String(e);
      }
      this.currentView = 'settings';
    },
    async saveSettings() {
      this.settingsError = '';
      try {
        await invoke('set_policy_settings', { settings: JSON.stringify(this.policy) });
        this.currentView = 'home';
      } catch (e) {
        this.settingsError = String(e);
      }
    },
    async toggleFileAuth(file: File, new_mode: AuthorizationMode) {
      let auth = 0;
      if (new_mode == AuthorizationMode.AllowRead) {
        auth = 1;
      } else if (new_mode == AuthorizationMode.AllowRW) {
        auth = 2;
      }
      invoke('toggle_file_auth', {device: file.device, id: file.id, path: file.path, newAuth: auth})
        .then(() => {
          file.authorization = new_mode;
        })
        .catch(() => alert("Toggle file authorization failed"));
    },
    async backToUsbList() {
      this.currentView = 'home';
      this.file_list = [];
      const win = getCurrentWebviewWindow();
      await win.hide();
    }
  },
};
</script>

<style scoped>
.app_container {
  position: absolute;
  left: 0px;
  right: 0px;
  top: 0px;
}

.app_icon {
  background: url('logo-keysas-short-48.png');
  background-size: 20px;
  height: 20px;
  width: 20px;
  display: block;
}

.app_title {
  width: 95%;
  text-align: start;
  padding-left: 2%;
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  border-bottom: 1px solid lightgray;
}

.placeholder {
  padding: 24px 16px;
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  font-size: 13px;
  color: #666;
  text-align: center;
}

.settings-view {
  padding: 12px 16px;
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  font-size: 13px;
}

.settings-view h3 {
  margin: 0 0 12px 0;
  font-size: 14px;
  border-bottom: 1px solid lightgray;
  padding-bottom: 6px;
}

.setting-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 10px;
  cursor: pointer;
}

.settings-actions {
  margin-top: 14px;
  display: flex;
  gap: 8px;
}

.settings-actions button {
  padding: 4px 14px;
  font-size: 12px;
  background: #e0e0e0;
  border: 1px solid #bbb;
  border-radius: 3px;
  cursor: pointer;
}

.settings-error {
  margin-top: 8px;
  color: red;
  font-size: 12px;
}

button {
  background-color: transparent;
}

table {
  border-collapse: collapse;
  width: 100%;
}

tbody tr td {
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  border-bottom: 1px solid grey;
}
</style>

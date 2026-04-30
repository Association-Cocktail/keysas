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
    <!-- Placeholder: shown when no device is selected from the tray menu -->
    <div v-if="!showUsbDetails" class="placeholder">
      Select a device from the system tray menu.
    </div>
    <!-- File details view -->
    <table v-if="showUsbDetails">
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
  authorization: number,
  blocked_files: string[],
  allow_user_file_write: boolean,
  allow_user_file_read: boolean,
  allow_user_usb_authorization: boolean
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
      showUsbDetails: false,
      file_list: [] as File[],
      usb_device: {} as UsbDevice,
    }
  },
  async mounted() {
    // Open the file-details view when the user clicks a device in the tray menu.
    await listen('show_device', (event) => {
      const device = event.payload as UsbDevice;
      this.showUsbDevice(device);
    });
    // Keep the file list up to date as files are scanned.
    await listen('file_update', (event) => {
      this.refreshFileList(event.payload as string);
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
      this.showUsbDetails = true;
    },
    async toggleFileAuth(file: File, new_mode: AuthorizationMode) {
      const auth = new_mode as number;
      invoke('toggle_file_auth', {device: file.device, id: file.id, path: file.path, newAuth: auth})
        .then(() => {
          file.authorization = new_mode;
        })
        .catch(() => alert("Toggle file authorization failed"));
    },
    async backToUsbList() {
      this.showUsbDetails = false;
      this.file_list = [];
      // The USB list lives in the native tray menu; just hide the window.
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

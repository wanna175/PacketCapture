#pragma once
#pragma once
#ifdef _DEBUG
#pragma comment(lib,"Debug\\pcaplib.lib")
#else
#pragma comment(lib,"Release\\pcaplib.lib")
#endif 

#include <wx/wx.h>
#include <wx/listbox.h>
#include <wx/textctrl.h>
#include <wx/panel.h>
#include <wx/statbox.h>
#include <wx/splitter.h>
#include <thread>
#include <atomic>
#include <unordered_map>

#include "pcaplib.h"
// 네트워크 디바이스 선택 패널
class DeviceSelectionPanel : public wxPanel {
public:
    DeviceSelectionPanel(wxWindow* parent);

private:
    void InitUI();

    void BindEvents();

    void PopulateDeviceList();

    void OnDeviceDoubleClicked(wxCommandEvent& event);

private:
    wxListBox* deviceList;
    std::unique_ptr<PacketCapture> capture;
    unordered_map<string, string> devs;
}; 



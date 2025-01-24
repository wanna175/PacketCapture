#include "DeviceSelectionPanel.h"
#include "CustomEvents.h"
DeviceSelectionPanel::DeviceSelectionPanel(wxWindow* parent)
    : wxPanel(parent), capture(std::make_unique<PacketCapture>()) {
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

    InitUI();
    BindEvents();
    PopulateDeviceList();
}

inline void DeviceSelectionPanel::BindEvents() {
    deviceList->Bind(wxEVT_LISTBOX_DCLICK, &DeviceSelectionPanel::OnDeviceDoubleClicked, this);
}

inline void DeviceSelectionPanel::InitUI() {
    wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);

    // 네트워크 디바이스 리스트
    wxStaticBoxSizer* deviceSizer = new wxStaticBoxSizer(wxVERTICAL, this, "Select a Network Device");
    deviceList = new wxListBox(this, wxID_ANY);
    deviceSizer->Add(deviceList, 1, wxEXPAND | wxALL, 5);
    mainSizer->Add(deviceSizer, 1, wxEXPAND | wxALL, 5);

    // Next 버튼 (아이콘 추가)
    /*wxImage::AddHandler(new wxPNGHandler());
    wxBitmap nextIcon("icons/next.png", wxBITMAP_TYPE_PNG);
    nextButton = new wxBitmapButton(this, wxID_ANY, nextIcon);
    mainSizer->Add(nextButton, 0, wxALIGN_CENTER | wxALL, 10);*/

    SetSizer(mainSizer);
}

inline void DeviceSelectionPanel::PopulateDeviceList() {
    if (!capture->initialize()) {
        wxMessageBox("Failed to initialize packet capture.", "Error", wxOK | wxICON_ERROR);
        return;
    }

    if (!capture->listDevices()) {
        wxMessageBox("No devices found.", "Error", wxOK | wxICON_ERROR);
        return;
    }

    for (const auto& dev : capture->getDeviceNames()) {
        //sec=>description first=>name
        devs[dev.second] = dev.first;
        deviceList->Append(wxString::FromUTF8(dev.second));
    }
}

void DeviceSelectionPanel::OnDeviceDoubleClicked(wxCommandEvent& event) {
    int selection = deviceList->GetSelection();
    if (selection == wxNOT_FOUND) {
        wxMessageBox("Please select a valid device.", "Warning", wxOK | wxICON_WARNING);
        return;
    }

    wxString selectedDevice = devs[(string)deviceList->GetString(selection)];

    // 선택한 네트워크 장치를 이벤트로 전달
    wxCommandEvent switchEvent(EVT_SWITCH_PANEL);
    switchEvent.SetString(selectedDevice); // 선택한 장치 이름 전달
    wxPostEvent(GetParent(), switchEvent);
}
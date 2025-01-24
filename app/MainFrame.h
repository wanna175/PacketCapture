#pragma once

#include <wx/wx.h>
#include "CustomEvents.h"
#include "PacketCapturePanel.h"
#include "DeviceSelectionPanel.h"
// 메인 프레임
class MainFrame : public wxFrame {
public:
    MainFrame(const wxString& title);

private:
    void OnSwitchPanel(wxCommandEvent& event); // 이벤트 핸들러
    wxDECLARE_EVENT_TABLE();

    void InitUI();
    void CreateMenuBar(); // 메뉴바 생성 메서드
    void SwitchToPanel(wxPanel* panel);

    // 메뉴 이벤트 핸들러
    void OnExit(wxCommandEvent& event);
    void OnAbout(wxCommandEvent& event);
    void OnSaveLog(wxCommandEvent& event);
private:
    wxPanel* currentPanel = nullptr;
    DeviceSelectionPanel* deviceSelectionPanel;
    PacketCapturePanel* packetCapturePanel;
};

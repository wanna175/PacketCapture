#pragma once

#include <wx/wx.h>
#include "CustomEvents.h"
#include "PacketCapturePanel.h"
#include "DeviceSelectionPanel.h"
// ���� ������
class MainFrame : public wxFrame {
public:
    MainFrame(const wxString& title);

private:
    void OnSwitchPanel(wxCommandEvent& event); // �̺�Ʈ �ڵ鷯
    wxDECLARE_EVENT_TABLE();

    void InitUI();
    void CreateMenuBar(); // �޴��� ���� �޼���
    void SwitchToPanel(wxPanel* panel);

    // �޴� �̺�Ʈ �ڵ鷯
    void OnExit(wxCommandEvent& event);
    void OnAbout(wxCommandEvent& event);
    void OnSaveLog(wxCommandEvent& event);
private:
    wxPanel* currentPanel = nullptr;
    DeviceSelectionPanel* deviceSelectionPanel;
    PacketCapturePanel* packetCapturePanel;
};

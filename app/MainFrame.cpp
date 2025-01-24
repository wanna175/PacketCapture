#include "MainFrame.h"

wxBEGIN_EVENT_TABLE(MainFrame, wxFrame)
EVT_MENU(wxID_EXIT, MainFrame::OnExit)
EVT_MENU(wxID_ABOUT, MainFrame::OnAbout)
EVT_MENU(wxID_SAVE, MainFrame::OnSaveLog)
EVT_COMMAND(wxID_ANY, EVT_SWITCH_PANEL, MainFrame::OnSwitchPanel)
wxEND_EVENT_TABLE()

MainFrame::MainFrame(const wxString& title)
    : wxFrame(nullptr, wxID_ANY, title, wxDefaultPosition, wxSize(800, 600)) {
    // �ʱ� �г� ����
    InitUI();
    CreateMenuBar();
}
void MainFrame::InitUI() {
    // �ʱ� �г� ����
    deviceSelectionPanel = new DeviceSelectionPanel(this);
    packetCapturePanel = new PacketCapturePanel(this,"");
    packetCapturePanel->Hide();

    wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
    mainSizer->Add(deviceSelectionPanel, 1, wxEXPAND);
    mainSizer->Add(packetCapturePanel, 1, wxEXPAND);

    SetSizer(mainSizer);
}

void MainFrame::CreateMenuBar() {
    wxMenuBar* menuBar = new wxMenuBar();

    // File �޴�
    wxMenu* fileMenu = new wxMenu();
    fileMenu->Append(wxID_SAVE, wxT("&Save Log...\tCtrl+S"), wxT("Save captured log to a file"));
    fileMenu->AppendSeparator();
    fileMenu->Append(wxID_EXIT, wxT("&Exit\tAlt+F4"), wxT("Quit the application"));

    // Help �޴�
    wxMenu* helpMenu = new wxMenu();
    helpMenu->Append(wxID_ABOUT, wxT("&About\tF1"), wxT("Show information about this application"));

    // �޴��ٿ� �޴� �߰�
    menuBar->Append(fileMenu, wxT("&File"));
    menuBar->Append(helpMenu, wxT("&Help"));

    SetMenuBar(menuBar);
}

void MainFrame::SwitchToPanel(wxPanel* panel)
{
    deviceSelectionPanel->Hide();
    packetCapturePanel->Hide();

    panel->Show();
    Layout(); // ���̾ƿ� ������Ʈ
}


void MainFrame::OnSwitchPanel(wxCommandEvent& event) {
    /*if (panelName == "DeviceSelection") {
        SetNewPanel(new DeviceSelectionPanel(this));
    }
    else if (panelName == "PacketCapture") {
        SetNewPanel(new PacketCapturePanel(this));
    }*/
    wxString selectedDevice = event.GetString();
    packetCapturePanel->setSelectedDevice((string)selectedDevice);
    SwitchToPanel(packetCapturePanel);
}
void MainFrame::OnExit(wxCommandEvent& event) {
    Close(true); // ���ø����̼� ����
}

void MainFrame::OnAbout(wxCommandEvent& event) {
    wxMessageBox("Packet Capture Tool\nDeveloped using wxWidgets.",
        "About", wxOK | wxICON_INFORMATION, this);
}

void MainFrame::OnSaveLog(wxCommandEvent& event) {
    wxFileDialog saveFileDialog(this, wxT("Save Log File"), "", "",
        "Text Files (*.txt)|*.txt", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);

    if (saveFileDialog.ShowModal() == wxID_CANCEL) {
        return; // ����ڰ� ��Ҹ� ������ ��
    }

    wxString path = saveFileDialog.GetPath();
    if (packetCapturePanel) {
        packetCapturePanel->SaveLogToFile(path);
    }
}
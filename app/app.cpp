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
#include "pcaplib.h"

struct PacketInfo {
    std::string summary;
    std::string details;
};

class FilterDialog : public wxDialog {
public:
    FilterDialog(wxWindow* parent) : wxDialog(parent, wxID_ANY, "���� ����", wxDefaultPosition, wxSize(400, 200)) {
        wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
        SetBackgroundColour(wxColour(240, 240, 240)); // ���� ȸ�� ���

        // ���� �Է� �ʵ� (����� ��Ÿ��)
        wxStaticText* label = new wxStaticText(this, wxID_ANY, "���� �Է� (��: IP, ��Ʈ):");
        label->SetForegroundColour(wxColour(50, 50, 50));

        filterInput = new wxTextCtrl(this, wxID_ANY, "", wxDefaultPosition, wxDefaultSize,
            wxBORDER_SIMPLE); // ����ȭ�� �׵θ�
        filterInput->SetBackgroundColour(wxColour(255, 255, 255));
        filterInput->SetForegroundColour(wxColour(0, 0, 0));

        mainSizer->Add(label, 0, wxLEFT | wxRIGHT | wxTOP, 15);
        mainSizer->Add(filterInput, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 15);

        // �������� ��ư ������
        wxBoxSizer* buttonSizer = new wxBoxSizer(wxHORIZONTAL);
        wxButton* okButton = new wxButton(this, wxID_OK, "����", wxDefaultPosition, wxDefaultSize, wxBORDER_NONE);
        wxButton* cancelButton = new wxButton(this, wxID_CANCEL, "���", wxDefaultPosition, wxDefaultSize, wxBORDER_NONE);

        // ��ư ���� �� ��Ÿ�� ����
        okButton->SetBackgroundColour(wxColour(52, 152, 219)); // �Ķ���
        okButton->SetForegroundColour(*wxWHITE);
        cancelButton->SetBackgroundColour(wxColour(231, 76, 60)); // ������
        cancelButton->SetForegroundColour(*wxWHITE);

        buttonSizer->Add(okButton, 1, wxEXPAND | wxALL, 5);
        buttonSizer->Add(cancelButton, 1, wxEXPAND | wxALL, 5);

        mainSizer->Add(buttonSizer, 0, wxALIGN_CENTER);

        SetSizerAndFit(mainSizer);
    }

    wxString GetFilter() const {
        return filterInput->GetValue();
    }

private:
    wxTextCtrl* filterInput;
};

class DetailsDialog : public wxDialog {
public:
    DetailsDialog(wxWindow* parent, const PacketInfo& packet)
        : wxDialog(parent, wxID_ANY, "��Ŷ �� ����", wxDefaultPosition, wxSize(500, 400)) {
        wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
        SetBackgroundColour(wxColour(240, 240, 240));

        // ��뽺���̽� ��Ʈ�� �� ���� ǥ��
        wxTextCtrl* detailsText = new wxTextCtrl(this, wxID_ANY,
            wxString::FromUTF8(packet.details),
            wxDefaultPosition, wxDefaultSize,
            wxTE_MULTILINE | wxTE_READONLY | wxBORDER_SIMPLE);

        detailsText->SetBackgroundColour(wxColour(255, 255, 255));
        detailsText->SetDefaultStyle(
            wxTextAttr(wxColour(0, 0, 0), wxColour(255, 255, 255),
                wxFont(10, wxFONTFAMILY_TELETYPE, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL))
        );

        sizer->Add(detailsText, 1, wxEXPAND | wxALL, 15);

        wxButton* closeButton = new wxButton(this, wxID_OK, "�ݱ�", wxDefaultPosition, wxDefaultSize, wxBORDER_NONE);
        closeButton->SetBackgroundColour(wxColour(52, 152, 219));
        closeButton->SetForegroundColour(*wxWHITE);
        sizer->Add(closeButton, 0, wxALIGN_CENTER | wxALL, 10);

        SetSizerAndFit(sizer);
    }
};
// ���� ������
class MainFrame : public wxFrame {
public:
    MainFrame(const wxString& title)
        : wxFrame(nullptr, wxID_ANY, title, wxDefaultPosition, wxSize(800, 600)) {
        // �ʱ� ȭ���� ��Ʈ��ũ ����̽� ���� �г�
        SetNewPanel(new DeviceSelectionPanel(this));
    }

    void SetNewPanel(wxPanel* newPanel) {
        if (currentPanel) {
            currentPanel->Destroy();
        }
        currentPanel = newPanel;
        Layout(); // ���̾ƿ� ������Ʈ
    }

private:
    wxPanel* currentPanel = nullptr;
};



// ��Ŷ ĸó �۾� �г�
class PacketCapturePanel : public wxPanel {
public:
    PacketCapturePanel(MainFrame* parent, const std::string& selectedDevice)
        : wxPanel(parent), mainFrame(parent), selectedDevice(selectedDevice),
        capture(std::make_unique<PacketCapture>()), isCapturing(false) {
        InitUI();
        BindEvents();
    }

    ~PacketCapturePanel() {
        if (isCapturing) {
            StopCapture();
        }
    }

private:
    wxListBox* packetList;
    wxBitmapButton* startButton;
    wxBitmapButton* stopButton;
    wxTextCtrl* packetLog;

    std::unique_ptr<PacketCapture> capture;
    std::atomic<bool> isCapturing;
    std::thread captureThread;

    std::vector<std::string> capturedPacketDetails;
    MainFrame* mainFrame;
    std::string selectedDevice;

    void InitUI() {
        wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);

        // ĸó�� ��Ŷ ����Ʈ
        wxStaticBoxSizer* packetSizer = new wxStaticBoxSizer(wxVERTICAL, this, "Captured Packets");
        packetList = new wxListBox(this, wxID_ANY);
        packetSizer->Add(packetList, 1, wxEXPAND | wxALL, 5);
        mainSizer->Add(packetSizer, 2, wxEXPAND | wxALL, 5);

        // ��ư ���̾ƿ� (������ �߰�)
        wxBoxSizer* buttonSizer = new wxBoxSizer(wxHORIZONTAL);
        wxImage::AddHandler(new wxPNGHandler());
        wxBitmap startIcon("icons/start.png", wxBITMAP_TYPE_PNG);
        wxBitmap stopIcon("icons/stop.png", wxBITMAP_TYPE_PNG);
        startButton = new wxBitmapButton(this, wxID_ANY, startIcon);
        stopButton = new wxBitmapButton(this, wxID_ANY, stopIcon);
        stopButton->Enable(false);
        buttonSizer->Add(startButton, 1, wxEXPAND | wxALL, 5);
        buttonSizer->Add(stopButton, 1, wxEXPAND | wxALL, 5);
        mainSizer->Add(buttonSizer, 0, wxALIGN_CENTER | wxALL, 10);

        // ��Ŷ �α�
        wxStaticBoxSizer* logSizer = new wxStaticBoxSizer(wxVERTICAL, this, "Packet Log");
        packetLog = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY);
        logSizer->Add(packetLog, 1, wxEXPAND | wxALL, 5);
        mainSizer->Add(logSizer, 2, wxEXPAND | wxALL, 5);

        SetSizer(mainSizer);
    }

    void BindEvents() {
        startButton->Bind(wxEVT_BUTTON, &PacketCapturePanel::OnStartCapture, this);
        stopButton->Bind(wxEVT_BUTTON, &PacketCapturePanel::OnStopCapture, this);
        packetList->Bind(wxEVT_LISTBOX_DCLICK, &PacketCapturePanel::OnPacketDoubleClick, this);
    }

    void OnStartCapture(wxCommandEvent& event) {
        if (!capture->startCapture(selectedDevice)) {
            wxMessageBox("Failed to start capture.", "Error", wxOK | wxICON_ERROR);
            return;
        }

        isCapturing = true;
        startButton->Enable(false);
        stopButton->Enable(true);

        captureThread = std::thread([this]() {
            capturePackets();
            });

        wxMessageBox("Capture started.", "Info", wxOK | wxICON_INFORMATION);
    }

    void OnStopCapture(wxCommandEvent& event) {
        StopCapture();
        wxMessageBox("Capture stopped.", "Info", wxOK | wxICON_INFORMATION);
    }

    void StopCapture() {
        if (!isCapturing) return;

        capture->stopCapture();
        isCapturing = false;

        if (captureThread.joinable()) {
            captureThread.join();
        }

        startButton->Enable(true);
        stopButton->Enable(false);
    }

    void capturePackets() {
        capturedPacketDetails.clear();
        capture->processPackets([this](const std::string& packetInfo) {
            CallAfter([this, packetInfo]() {
                packetList->Append(wxString::FromUTF8(packetInfo));
                capturedPacketDetails.push_back(packetInfo);
                });
            });
    }

    void OnPacketDoubleClick(wxCommandEvent& event) {
        int selection = packetList->GetSelection();
        if (selection != wxNOT_FOUND && selection < capturedPacketDetails.size()) {
            packetLog->AppendText("Details of Selected Packet:\n");
            packetLog->AppendText(wxString::FromUTF8(capturedPacketDetails[selection]) + "\n\n");
        }
    }
};
// ��Ʈ��ũ ����̽� ���� �г�
class DeviceSelectionPanel : public wxPanel {
public:
    DeviceSelectionPanel(MainFrame* parent)
        : wxPanel(parent), mainFrame(parent), capture(std::make_unique<PacketCapture>()) {
        InitUI();
        BindEvents();
        PopulateDeviceList();
    }

private:
    wxListBox* deviceList;
    wxButton* nextButton;
    std::unique_ptr<PacketCapture> capture;
    MainFrame* mainFrame;

    void InitUI() {
        wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);

        // ��Ʈ��ũ ����̽� ����Ʈ
        wxStaticBoxSizer* deviceSizer = new wxStaticBoxSizer(wxVERTICAL, this, "Select a Network Device");
        deviceList = new wxListBox(this, wxID_ANY);
        deviceSizer->Add(deviceList, 1, wxEXPAND | wxALL, 5);
        mainSizer->Add(deviceSizer, 1, wxEXPAND | wxALL, 5);

        // Next ��ư (������ �߰�)
        wxImage::AddHandler(new wxPNGHandler());
        wxBitmap nextIcon("icons/next.png", wxBITMAP_TYPE_PNG);
        nextButton = new wxBitmapButton(this, wxID_ANY, nextIcon);
        mainSizer->Add(nextButton, 0, wxALIGN_CENTER | wxALL, 10);

        SetSizer(mainSizer);
    }

    void BindEvents() {
        nextButton->Bind(wxEVT_BUTTON, &DeviceSelectionPanel::OnNextClicked, this);
    }

    void PopulateDeviceList() {
        if (!capture->initialize()) {
            wxMessageBox("Failed to initialize packet capture.", "Error", wxOK | wxICON_ERROR);
            return;
        }

        if (!capture->listDevices()) {
            wxMessageBox("No devices found.", "Error", wxOK | wxICON_ERROR);
            return;
        }

        for (const auto& dev : capture->getDeviceNames()) {
            deviceList->Append(wxString::FromUTF8(dev));
        }
    }

    void OnNextClicked(wxCommandEvent& event) {
        int selection = deviceList->GetSelection();
        if (selection == wxNOT_FOUND) {
            wxMessageBox("Please select a device.", "Warning", wxOK | wxICON_WARNING);
            return;
        }

        wxString selectedDevice = deviceList->GetString(selection);
        mainFrame->SetNewPanel(new PacketCapturePanel(mainFrame, std::string(selectedDevice.mb_str())));
    }
};
// wxApp ����
class PacketCaptureApp : public wxApp {
public:
    virtual bool OnInit() override {
        MainFrame* frame = new MainFrame("Packet Capture Tool");
        frame->Show(true);
        return true;
    }
};

wxIMPLEMENT_APP(PacketCaptureApp);
//class MainFrame : public wxFrame {
//public:
//    MainFrame(const wxString& title)
//        : wxFrame(nullptr, wxID_ANY, title, wxDefaultPosition, wxSize(1200, 800)),
//        capture(std::make_unique<PacketCapture>()), isCapturing(false) {
//        InitUI();
//        BindEvents();
//    }
//    ~MainFrame() {
//        if (isCapturing) {
//            StopCapture();
//        }
//    }
//private:
//    wxListBox* deviceList;
//    wxButton* startButton;
//    wxButton* stopButton;
//    wxListBox* packetList;
//    wxTextCtrl* packetLog;
//
//    std::unique_ptr<PacketCapture> capture;
//    std::atomic<bool> isCapturing;
//    std::thread captureThread;
//    std::vector<PacketInfo> packets;
//    wxString filter;
//
//    std::vector<std::string> capturedPacketDetails; // ��Ŷ �� ������ �����ϴ� ����
//
//    void InitUI() {
//        // �޴��� ����
//        wxMenuBar* menuBar = new wxMenuBar;
//
//        wxMenu* fileMenu = new wxMenu;
//        fileMenu->Append(wxID_EXIT, "Exit\tCtrl+Q");
//        menuBar->Append(fileMenu, "File");
//
//        wxMenu* filterMenu = new wxMenu;
//        filterMenu->Append(wxID_ANY, "Set Filter");
//        menuBar->Append(filterMenu, "Filter");
//
//        SetMenuBar(menuBar);
//
//        wxPanel* panel = new wxPanel(this);
//        wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
//
//        // ��Ʈ��ũ ����̽� ����Ʈ
//        wxStaticBoxSizer* deviceSizer = new wxStaticBoxSizer(wxVERTICAL, panel, "Network Devices");
//        deviceList = new wxListBox(panel, wxID_ANY);
//        deviceSizer->Add(deviceList, 1, wxEXPAND | wxALL, 5);
//        mainSizer->Add(deviceSizer, 1, wxEXPAND | wxALL, 5);
//
//        // ĸó�� ��Ŷ ����Ʈ
//        wxStaticBoxSizer* packetSizer = new wxStaticBoxSizer(wxVERTICAL, panel, "Captured Packets");
//        packetList = new wxListBox(panel, wxID_ANY);
//        packetSizer->Add(packetList, 1, wxEXPAND | wxALL, 5);
//        mainSizer->Add(packetSizer, 2, wxEXPAND | wxALL, 5);
//
//        // ��ư ���̾ƿ�
//        wxBoxSizer* buttonSizer = new wxBoxSizer(wxHORIZONTAL);
//        startButton = new wxButton(panel, wxID_ANY, "Start Capture");
//        stopButton = new wxButton(panel, wxID_ANY, "Stop Capture");
//        stopButton->Enable(false); // �ʱ� ���¿��� Stop ��ư�� ��Ȱ��ȭ
//        buttonSizer->Add(startButton, 1, wxEXPAND | wxALL, 5);
//        buttonSizer->Add(stopButton, 1, wxEXPAND | wxALL, 5);
//
//        mainSizer->Add(buttonSizer, 0, wxALIGN_CENTER | wxALL, 10);
//
//        // ��Ŷ �α�
//        wxStaticBoxSizer* logSizer = new wxStaticBoxSizer(wxVERTICAL, panel, "Packet Log");
//        packetLog = new wxTextCtrl(panel, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY);
//        logSizer->Add(packetLog, 1, wxEXPAND | wxALL, 5);
//        mainSizer->Add(logSizer, 2, wxEXPAND | wxALL, 5);
//
//        panel->SetSizer(mainSizer);
//        mainSizer->SetSizeHints(this);
//
//        PopulateDeviceList();
//    }
//
//    void BindEvents() {
//        Bind(wxEVT_MENU, &MainFrame::OnExit, this, wxID_EXIT);
//        Bind(wxEVT_MENU, &MainFrame::OnSetFilter, this);
//        startButton->Bind(wxEVT_BUTTON, &MainFrame::OnStartCapture, this);
//        stopButton->Bind(wxEVT_BUTTON, &MainFrame::OnStopCapture, this);
//        packetList->Bind(wxEVT_LISTBOX_DCLICK, &MainFrame::OnPacketDoubleClick, this); // ���� Ŭ�� �̺�Ʈ ���ε�
//    }
//    void OnExit(wxCommandEvent& event) {
//        Close(true);
//    }
//
//    void OnSetFilter(wxCommandEvent& event) {
//        FilterDialog dialog(this);
//        if (dialog.ShowModal() == wxID_OK) {
//            filter = dialog.GetFilter();
//            ApplyFilter();
//        }
//    }
//
//    void ApplyFilter() {
//        packetList->Clear();
//        for (const auto& packet : packets) {
//            if (filter.IsEmpty() || wxString::FromUTF8(packet.details).Contains(filter)) {
//                packetList->Append(wxString::FromUTF8(packet.summary));
//            }
//        }
//    }
//    void PopulateDeviceList() {
//        if (!capture->initialize()) {
//            wxMessageBox("Failed to initialize packet capture.", "Error", wxOK | wxICON_ERROR);
//            return;
//        }
//
//        if (!capture->listDevices()) {
//            wxMessageBox("No devices found.", "Error", wxOK | wxICON_ERROR);
//            return;
//        }
//
//        for (const auto& dev : capture->getDeviceNames()) {
//            deviceList->Append(wxString::FromUTF8(dev));
//        }
//    }
//
//    void OnStartCapture(wxCommandEvent& event) {
//        int selection = deviceList->GetSelection();
//        if (selection == wxNOT_FOUND) {
//            wxMessageBox("Please select a device to start capture.", "Warning", wxOK | wxICON_WARNING);
//            return;
//        }
//
//        wxString selectedDevice = deviceList->GetString(selection);
//
//        if (!capture->startCapture(std::string(selectedDevice.mb_str()))) {
//            wxMessageBox("Failed to start capture.", "Error", wxOK | wxICON_ERROR);
//            return;
//        }
//
//        isCapturing = true;
//        startButton->Enable(false);
//        stopButton->Enable(true);
//
//        // ĸó ������ ����
//        captureThread = std::thread([this]() {
//            capturePackets();
//            });
//
//        wxMessageBox("Capture started.", "Info", wxOK | wxICON_INFORMATION);
//    }
//
//    void OnStopCapture(wxCommandEvent& event) {
//        StopCapture();
//        wxMessageBox("Capture stopped.", "Info", wxOK | wxICON_INFORMATION);
//    }
//
//    void StopCapture() {
//        if (!isCapturing) return;
//
//        capture->stopCapture();
//        isCapturing = false;
//
//        if (captureThread.joinable()) {
//            captureThread.join();
//        }
//
//        startButton->Enable(true);
//        stopButton->Enable(false);
//    }
//
//    void capturePackets() {
//        capturedPacketDetails.clear(); // ���� ĸó�� ��Ŷ �ʱ�ȭ
//        capture->processPackets([this](const std::string& packetInfo) {
//            CallAfter([this, packetInfo]() {
//                packetList->Append(wxString::FromUTF8(packetInfo)); // ����Ʈ�� ��Ŷ �߰�
//                capturedPacketDetails.push_back(packetInfo); // �� ���� ����
//                });
//            });
//    }
//    void OnPacketDoubleClick(wxCommandEvent& event) {
//        int selection = packetList->GetSelection();
//        if (selection != wxNOT_FOUND && selection < capturedPacketDetails.size()) {
//            packetLog->AppendText("Details of Selected Packet:\n");
//            packetLog->AppendText(wxString::FromUTF8(capturedPacketDetails[selection]) + "\n\n");
//        }
//    }
//};
//
//// wxApp ����
//class PacketCaptureApp : public wxApp {
//public:
//    virtual bool OnInit() override {
//        MainFrame* frame = new MainFrame(wxT("Packet Capture Tool"));
//        frame->Show(true);
//        return true;
//    }
//};
//
//wxIMPLEMENT_APP(PacketCaptureApp);

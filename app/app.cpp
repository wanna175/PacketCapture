#ifdef _DEBUG
#pragma comment(lib,"Debug\\pcaplib.lib")
#else
#pragma comment(lib,"Release\\pcaplib.lib")
#endif 


#include <wx/wx.h>
#include <wx/listbox.h>
#include <wx/textctrl.h>
#include <thread>
#include <atomic>
#include "pcaplib.h" // ����ڰ� ���� PacketCapture Ŭ���� ����

// ��Ŷ ������ �����ϴ� ����ü
struct PacketInfo {
    std::string summary; // ������ ��Ŷ ����
    std::string details; // ��Ŷ�� �� ����
};
class FilterDialog : public wxDialog {
public:
    FilterDialog(wxWindow* parent)
        : wxDialog(parent, wxID_ANY, "Set Filter", wxDefaultPosition, wxSize(400, 200)) {
        wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);

        // ���� �Է� �ʵ�
        wxStaticText* label = new wxStaticText(this, wxID_ANY, "Enter filter (e.g., IP, port):");
        filterInput = new wxTextCtrl(this, wxID_ANY);

        mainSizer->Add(label, 0, wxLEFT | wxRIGHT | wxTOP, 10);
        mainSizer->Add(filterInput, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10);

        // ��ư ���̾ƿ�
        wxBoxSizer* buttonSizer = new wxBoxSizer(wxHORIZONTAL);
        wxButton* okButton = new wxButton(this, wxID_OK, "Apply");
        wxButton* cancelButton = new wxButton(this, wxID_CANCEL, "Cancel");

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
        : wxDialog(parent, wxID_ANY, "Packet Details", wxDefaultPosition, wxSize(500, 400)) {
        wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

        // �� ������ ����ϴ� �ؽ�Ʈ ��Ʈ��
        wxTextCtrl* detailsText = new wxTextCtrl(this, wxID_ANY, wxString::FromUTF8(packet.details),
            wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY);
        sizer->Add(detailsText, 1, wxEXPAND | wxALL, 10);

        wxButton* closeButton = new wxButton(this, wxID_OK, "Close");
        sizer->Add(closeButton, 0, wxALIGN_CENTER | wxALL, 10);

        SetSizerAndFit(sizer);
    }
};

class MainFrame : public wxFrame {
public:
    MainFrame(const wxString& title)
        : wxFrame(nullptr, wxID_ANY, title, wxDefaultPosition, wxSize(1000, 700)),
        capture(std::make_unique<PacketCapture>()), isCapturing(false) {
        InitUI();
        BindEvents();
    }

    ~MainFrame() {
        if (isCapturing) {
            StopCapture();
        }
    }

private:
    wxListBox* deviceList;
    wxButton* startButton;
    wxButton* stopButton;
    wxListBox* packetList; //packet��� ǥ��
    wxTextCtrl* packetLog;

    std::unique_ptr<PacketCapture> capture;
    std::atomic<bool> isCapturing;
    std::thread captureThread;
    std::vector<PacketInfo> packets; // ĸó�� ��Ŷ ������ ����
    wxString filter; // ���� ���ڿ�

    void InitUI() {
        // �޴��� ����
        wxMenuBar* menuBar = new wxMenuBar;
        // ���� �޴�
        wxMenu* fileMenu = new wxMenu;
        fileMenu->Append(wxID_EXIT, "Exit\tCtrl+Q");
        menuBar->Append(fileMenu, "File");

        // ���� �޴�
        wxMenu* filterMenu = new wxMenu;
        filterMenu->Append(wxID_ANY, "Set Filter");
        menuBar->Append(filterMenu, "Filter");
        wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);

        // ��Ʈ��ũ ����̽� ����Ʈ
        deviceList = new wxListBox(this, wxID_ANY);
        mainSizer->Add(deviceList, 1, wxEXPAND | wxALL, 5);

        // ��ư ���̾ƿ�
        wxBoxSizer* buttonSizer = new wxBoxSizer(wxHORIZONTAL);
        startButton = new wxButton(this, wxID_ANY, wxT("Start Capture"));
        stopButton = new wxButton(this, wxID_ANY, wxT("Stop Capture"));
        stopButton->Enable(false); // �ʱ⿡�� ��Ȱ��ȭ
        buttonSizer->Add(startButton, 1, wxEXPAND | wxALL, 5);
        buttonSizer->Add(stopButton, 1, wxEXPAND | wxALL, 5);
        mainSizer->Add(buttonSizer, 0, wxEXPAND | wxALL, 5);

        // ��Ŷ ��� ���
        packetList = new wxListBox(this, wxID_ANY);
        mainSizer->Add(packetList, 2, wxEXPAND | wxALL, 5);
        //// ��Ŷ �α� ���
        //packetLog = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY);
        //mainSizer->Add(packetLog, 2, wxEXPAND | wxALL, 5);

        SetSizer(mainSizer);

        // ��Ʈ��ũ ����̽� ��� �ʱ�ȭ
        PopulateDeviceList();
    }

    void BindEvents() {
        startButton->Bind(wxEVT_BUTTON, &MainFrame::OnStartCapture, this);
        stopButton->Bind(wxEVT_BUTTON, &MainFrame::OnStopCapture, this);
        packetList->Bind(wxEVT_LISTBOX_DCLICK, &MainFrame::OnPacketDoubleClicked, this);
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

    void OnStartCapture(wxCommandEvent& event) {
        int selection = deviceList->GetSelection();
        if (selection == wxNOT_FOUND) {
            wxMessageBox("Please select a device to start capture.", "Warning", wxOK | wxICON_WARNING);
            return;
        }

        wxString selectedDevice = deviceList->GetString(selection);

        if (!capture->startCapture(std::string(selectedDevice.mb_str()))) {
            wxMessageBox("Failed to start capture.", "Error", wxOK | wxICON_ERROR);
            return;
        }

        isCapturing = true;
        startButton->Enable(false);
        stopButton->Enable(true);

        // ĸó ������ ����
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
        capture->processPackets([this](const std::string& packetInfo) {
            PacketInfo packet = { packetInfo, "Detailed packet information for: " + packetInfo };
            packets.push_back(packet);

            CallAfter([this, packet]() {
                packetList->Append(wxString::FromUTF8(packet.summary));
                });
            });
    }
    void OnPacketDoubleClicked(wxCommandEvent& event) {
        int selection = packetList->GetSelection();
        if (selection != wxNOT_FOUND && selection < static_cast<int>(packets.size())) {
            PacketInfo& packet = packets[selection];
            DetailsDialog dialog(this, packet);
            dialog.ShowModal();
        }
    }
};

// wxApp ����
class PacketCaptureApp : public wxApp {
public:
    virtual bool OnInit() override {
        MainFrame* frame = new MainFrame(wxT("Packet Capture Tool"));
        frame->Show(true);
        return true;
    }
};

wxIMPLEMENT_APP(PacketCaptureApp);

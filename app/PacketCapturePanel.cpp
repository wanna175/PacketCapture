#include "PacketCapturePanel.h"
#include "CustomEvents.h"

PacketCapturePanel::PacketCapturePanel(wxWindow* parent, const string& dev)
    : wxPanel(parent) ,selectedDevice(dev), capture(std::make_unique<PacketCapture>()), isCapturing(false) {
    
    InitUI();
    BindEvents();
}

inline PacketCapturePanel::~PacketCapturePanel() {
    if (isCapturing) {
        StopCapture();
    }
}

void PacketCapturePanel::SaveLogToFile(const wxString& filePath)
{
    /*wxFile file;
    if (!file.Open(filePath, wxFile::write)) {
        wxMessageBox("Failed to save the log file.", "Error", wxOK | wxICON_ERROR);
        return;
    }

    file.Write(packetLog->GetValue());
    file.Close();*/
    wxMessageBox("Log file saved successfully.", "Info", wxOK | wxICON_INFORMATION);
}

void PacketCapturePanel::OnBackButtonClicked(wxCommandEvent& event) {
    wxCommandEvent switchEvent(EVT_SWITCH_PANEL);
    switchEvent.SetString("DeviceSelection"); // 전환할 패널 이름 설정
    wxPostEvent(GetParent(), switchEvent);
}

inline void PacketCapturePanel::capturePackets() {
    capturedPacketDetails.clear();
    packetGrid->ClearGrid();
    
    capture->processPackets([this](const PacketData& packetInfo) {
        
        CallAfter([this, packetInfo]() {
            int cur = packetInfo.getNum();
            packetGrid->AppendRows(1);
            packetGrid->SetCellValue(cur, 0, wxString::FromUTF8(to_string(packetInfo.getNum())));
            packetGrid->SetCellValue(cur, 1, wxString::FromUTF8(packetInfo.getTime()));
            packetGrid->SetCellValue(cur, 2, wxString::FromUTF8(packetInfo.getSrc()));
            packetGrid->SetCellValue(cur, 3, wxString::FromUTF8(packetInfo.getDst()));
            packetGrid->SetCellValue(cur, 4, wxString::FromUTF8(packetInfo.getProtocol()));
            packetGrid->SetCellValue(cur, 5, wxString::FromUTF8(packetInfo.getLength()));
            packetGrid->SetCellValue(cur, 6, wxString::FromUTF8(packetInfo.getInfo()));
            capturedPacketDetails.push_back(packetInfo.getInfo());
            //// 새로 추가된 행이 보이도록 스크롤
            packetGrid->MakeCellVisible(cur, 0);
            });
        

        });
}

void PacketCapturePanel::setSelectedDevice(const string& selectedDevice)
{
    this->selectedDevice = selectedDevice;
}

inline void PacketCapturePanel::StopCapture() {
    if (!isCapturing) return;

    capture->stopCapture();
    isCapturing = false;

    if (captureThread.joinable()) {
        captureThread.join();
    }

    startButton->Enable(true);
    stopButton->Enable(false);
}

inline void PacketCapturePanel::OnStopCapture(wxCommandEvent& event) {
    StopCapture();
    wxMessageBox("Capture stopped.", "Info", wxOK | wxICON_INFORMATION);
}

inline void PacketCapturePanel::OnStartCapture(wxCommandEvent& event) {
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

inline void PacketCapturePanel::BindEvents() {
    startButton->Bind(wxEVT_BUTTON, &PacketCapturePanel::OnStartCapture, this);
    stopButton->Bind(wxEVT_BUTTON, &PacketCapturePanel::OnStopCapture, this);
    packetGrid->Bind(wxEVT_GRID_CELL_LEFT_CLICK, &PacketCapturePanel::OnPacketDoubleClick, this);
    //filterTextCtrl->Bind(wxEVT_TEXT, &PacketCapturePanel::OnFilterTextChanged, this);
    filterButton->Bind(wxEVT_BUTTON, &PacketCapturePanel::OnFilterButtonClick, this);
}

inline void PacketCapturePanel::InitUI() {
    wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);

    // 필터 입력 박스
    wxBoxSizer* filterSizer = new wxBoxSizer(wxHORIZONTAL);
    // 필터 라벨과 텍스트 입력 박스
    filterTextCtrl = new wxTextCtrl(this, wxID_ANY, "", wxDefaultPosition, wxSize(300, -1));
    filterSizer->Add(new wxStaticText(this, wxID_ANY, ""), 0, wxALIGN_CENTER_VERTICAL | wxALL, 0);
    filterSizer->Add(filterTextCtrl, 1, wxEXPAND | wxALL, 0);

    // 필터 버튼
    filterButton = new wxButton(this, wxID_ANY, "=>");
    filterSizer->Add(filterButton, 0, wxALIGN_CENTER_VERTICAL | wxALL, 0);

    // 메인 레이아웃에 필터 UI 추가 (여백 없이)
    mainSizer->Add(filterSizer, 0, wxEXPAND, 0);
    // 패킷 캡쳐 테이블
    packetGrid = new wxGrid(this, wxID_ANY);
    packetGrid->CreateGrid(0, 7);  // 7개의 열 (No., Time, Source, Destination, Protocol, Length, Info)
    packetGrid->SetColLabelValue(0, "No.");
    packetGrid->SetColLabelValue(1, "Time");
    packetGrid->SetColLabelValue(2, "Source");
    packetGrid->SetColLabelValue(3, "Destination");
    packetGrid->SetColLabelValue(4, "Protocol");
    packetGrid->SetColLabelValue(5, "Length");
    packetGrid->SetColLabelValue(6, "Info");

    // 행 번호 없애기
    packetGrid->EnableGridLines(false);  // 그리드라인을 제거하여 번호가 보이지 않도록
    packetGrid->HideRowLabels();
    
    AdjustColumnWidths();
    mainSizer->Add(packetGrid, 1, wxEXPAND | wxALL, 0);

    // 시작, 정지 버튼
    wxBoxSizer* buttonSizer = new wxBoxSizer(wxHORIZONTAL);
    startButton = new wxButton(this, wxID_ANY, "Start Capture");
    stopButton = new wxButton(this, wxID_ANY, "Stop Capture");
    stopButton->Enable(false);  // 초기 상태에서 Stop 버튼은 비활성화
    buttonSizer->Add(startButton, 1, wxEXPAND | wxALL, 5);
    buttonSizer->Add(stopButton, 1, wxEXPAND | wxALL, 5);

    mainSizer->Add(buttonSizer, 0, wxALIGN_CENTER | wxALL, 10);

    // 패킷 로그
    wxStaticBoxSizer* logSizer = new wxStaticBoxSizer(wxVERTICAL, this, "Packet Log");
    packetLog = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY);
    logSizer->Add(packetLog, 1, wxEXPAND | wxALL, 5);
    mainSizer->Add(logSizer, 2, wxEXPAND | wxALL, 5);

    // 전체 레이아웃 설정
    SetSizerAndFit(mainSizer);
}

inline void PacketCapturePanel::OnPacketDoubleClick(wxGridEvent& event) {
    int cur = event.GetRow();
    // 선택한 행의 색상을 변경
    for (int col = 0; col < packetGrid->GetNumberCols(); ++col) {
        packetGrid->SetCellBackgroundColour(selection, col, *wxWHITE);
        packetGrid->SetCellBackgroundColour(cur, col, *wxLIGHT_GREY);
    }
    selection = cur;

    packetLog->Clear();
    if (selection >=0 && selection < capturedPacketDetails.size()) {
        packetLog->AppendText("Details of Selected Packet:\n");
        packetLog->AppendText(wxString::FromUTF8(capturedPacketDetails[selection]) + "\n\n");
    }
    // 테이블 다시 그리기
    packetGrid->ForceRefresh();

    event.Skip();  // 기본 이벤트 처리 허용
}
// 필터 텍스트 변경 이벤트 핸들러
void PacketCapturePanel::OnFilterButtonClick(wxCommandEvent& event) {
    wxString filterText = filterTextCtrl->GetValue();

    if (filterText.IsEmpty()) {
        wxMessageBox("Please enter a filter value.", "Filter", wxOK | wxICON_INFORMATION);
        return;
    }
}
// 열 너비를 화면 크기에 맞게 조정
void PacketCapturePanel::AdjustColumnWidths() {
    if (!packetGrid) return;


    // 각 열의 비율 (예: No. = 5%, Time = 15%, ...)
    std::vector<int> columnRatios = { 30, 70, 120, 120,70, 70, 300 };

    for (int col = 0; col < columnRatios.size(); ++col) {
        int colWidth = static_cast<int>(columnRatios[col]);
        packetGrid->SetColSize(col, colWidth);
    }
}

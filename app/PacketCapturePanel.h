#pragma once
#ifdef _DEBUG
#pragma comment(lib,"Debug\\pcaplib.lib")
#else
#pragma comment(lib,"Release\\pcaplib.lib")
#endif 

#include <wx/wx.h>
#include <wx/grid.h>
#include <wx/panel.h>
#include <wx/textctrl.h>
#include <wx/collpane.h>
#include <wx/listbox.h>
#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <map>
#include "pcaplib.h"

class PacketCapturePanel : public wxPanel {
public:
    PacketCapturePanel(wxWindow* parent,const string& dev);
    ~PacketCapturePanel();

    void SaveLogToFile(const wxString& filePath);
    void setSelectedDevice(const string& selectedDevice);
private:
    void OnBackButtonClicked(wxCommandEvent& event);
    void InitUI();

    void BindEvents();

    void OnStartCapture(wxCommandEvent& event);

    void OnStopCapture(wxCommandEvent& event);

    void StopCapture();

    void capturePackets();

    void OnPacketDoubleClick(wxGridEvent& event);

    void OnFilterButtonClick(wxCommandEvent& event);

    void AdjustColumnWidths();

    void ApplyColorToPacketRow(int row, const PacketData& packetInfo);

private:
   /* wxBitmapButton* startButton;
    wxBitmapButton* stopButton;*/
    wxButton* startButton; //캡쳐 시작 버튼
    wxButton* stopButton;  //캡쳐 중지 버튼
    wxTextCtrl* packetLog; //패킷 디테일 화면
    wxGrid* packetGrid;// 패킷 테이블
    wxTextCtrl* filterTextCtrl;//필터 text
    wxButton* filterButton; //필터 버튼
    //wxTextCtrl* rawPacketDisplay;
    //wxTextCtrl* detailedLogDisplay;
    // 
    //테이블에서 선택된 row, color
    int selection = -1;
    wxColour* selectionCol;

    unique_ptr<PacketCapture> capture;
    atomic<bool> isCapturing;
    thread captureThread;
    
    vector<string> capturedPacketDetails;
    
    string selectedDevice;

    map<string, wxColour> ipColorMap;
    map<int, wxColour> rowColorMap;
    vector<wxColour> availableColors = {
        wxColour(255, 235, 238), // 연한 핑크
        wxColour(232, 245, 233), // 연한 그린
        wxColour(227, 242, 253), // 연한 블루
        wxColour(248, 251, 253), // 연한 하늘색
        wxColour(255, 249, 196), // 연한 옐로우
        wxColour(255, 243, 224), // 연한 오렌지
        wxColour(240, 244, 195), // 연한 연두색
        wxColour(237, 231, 246)  // 연한 퍼플
    };
};

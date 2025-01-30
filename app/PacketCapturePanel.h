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
    wxButton* startButton; //ĸ�� ���� ��ư
    wxButton* stopButton;  //ĸ�� ���� ��ư
    wxTextCtrl* packetLog; //��Ŷ ������ ȭ��
    wxGrid* packetGrid;// ��Ŷ ���̺�
    wxTextCtrl* filterTextCtrl;//���� text
    wxButton* filterButton; //���� ��ư
    //wxTextCtrl* rawPacketDisplay;
    //wxTextCtrl* detailedLogDisplay;
    // 
    //���̺��� ���õ� row, color
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
        wxColour(255, 235, 238), // ���� ��ũ
        wxColour(232, 245, 233), // ���� �׸�
        wxColour(227, 242, 253), // ���� ���
        wxColour(248, 251, 253), // ���� �ϴû�
        wxColour(255, 249, 196), // ���� ���ο�
        wxColour(255, 243, 224), // ���� ������
        wxColour(240, 244, 195), // ���� ���λ�
        wxColour(237, 231, 246)  // ���� ����
    };
};

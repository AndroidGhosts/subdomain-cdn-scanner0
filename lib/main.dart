import 'package:flutter/material.dart';
import 'dart:io';
import 'dart:async';

void main() => runApp(SubdomainScannerApp());

class SubdomainScannerApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Subdomain & CDN Scanner',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: ScannerScreen(),
    );
  }
}

class ScannerScreen extends StatefulWidget {
  @override
  _ScannerScreenState createState() => _ScannerScreenState();
}

class _ScannerScreenState extends State<ScannerScreen> {
  final TextEditingController _domainController = TextEditingController();
  List<String> _results = [];
  bool _isScanning = false;

  Future<void> _scanDomain() async {
    final domain = _domainController.text.trim();
    if (domain.isEmpty) {
      setState(() => _results = ['❌ Please enter a domain']);
      return;
    }

    setState(() {
      _isScanning = true;
      _results = ['🔍 Scanning $domain...'];
    });

    // النطاقات الفرعية للفحص (من كودك الأصلي)
    final subdomains = [
      'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'test', 'dev',
      'shop', 'news', 'cdn', 'static', 'assets', 'media', 'img'
    ];

    for (final sub in subdomains) {
      final fullDomain = '$sub.$domain';
      
      setState(() => _results.add('🌐 $fullDomain → Checking...'));

      try {
        final addresses = await InternetAddress.lookup(fullDomain);
        if (addresses.isNotEmpty) {
          final ip = addresses.first.address;
          // كشف CDN مبسط
          final cdn = _detectCDN(ip, fullDomain);
          setState(() => _results[_results.length - 1] = '✅ $fullDomain → $ip $cdn');
        }
      } catch (e) {
        setState(() => _results[_results.length - 1] = '❌ $fullDomain → Not found');
      }

      await Future.delayed(Duration(milliseconds: 300));
    }

    setState(() {
      _isScanning = false;
      _results.add('✅ Scan completed! Found ${_results.where((r) => r.contains('✅')).length} subdomains');
    });
  }

  String _detectCDN(String ip, String domain) {
    final cdnPatterns = {
      'Cloudflare': ['cloudflare'],
      'CloudFront': ['cloudfront'],
      'Akamai': ['akamai'],
      'Fastly': ['fastly'],
    };
    
    // محاولة كشف CDN بناءً على IP أو اسم النطاق
    for (final entry in cdnPatterns.entries) {
      for (final pattern in entry.value) {
        if (domain.toLowerCase().contains(pattern) || ip.toLowerCase().contains(pattern)) {
          return '(${entry.key})';
        }
      }
    }
    return '';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Subdomain & CDN Scanner')),
      body: Padding(
        padding: EdgeInsets.all(16.0),
        child: Column(
          children: [
            TextField(
              controller: _domainController,
              decoration: InputDecoration(
                labelText: 'Enter domain (e.g. example.com)',
                border: OutlineInputBorder(),
              ),
            ),
            SizedBox(height: 20),
            ElevatedButton(
              onPressed: _isScanning ? null : _scanDomain,
              child: _isScanning ? CircularProgressIndicator() : Text('Start Scan'),
            ),
            SizedBox(height: 20),
            Expanded(
              child: ListView.builder(
                itemCount: _results.length,
                itemBuilder: (context, index) => Card(
                  child: ListTile(title: Text(_results[index])),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

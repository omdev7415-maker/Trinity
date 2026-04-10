document.addEventListener('DOMContentLoaded', () => {
    const chartDom = document.getElementById('map-container');
    const myChart = echarts.init(chartDom);
    
    const uiLoader = document.getElementById('loader');
    const feedContainer = document.getElementById('feed-container');
    
    // Toggles
    const btn3d = document.getElementById('btn-3d');
    const btn2d = document.getElementById('btn-2d');
    
    let is3DMode = true;
    let liveThreatsPool = [];
    let activeLines = [];
    
    // ECharts Styling Base
    const colorPalette = ['#ef4444', '#f59e0b', '#ec4899', '#6366f1'];
    
    // Hide Loader when ready
    setTimeout(() => {
        uiLoader.style.opacity = '0';
        setTimeout(() => uiLoader.style.display = 'none', 500);
    }, 1500);

    function get3DOption(dataLines) {
        return {
            backgroundColor: '#030305',
            globe: {
                baseTexture: 'https://cdn.jsdelivr.net/gh/apache/echarts-website@asf-site/examples/data-gl/asset/world.topo.bathy.200401.jpg',
                heightTexture: 'https://cdn.jsdelivr.net/gh/apache/echarts-website@asf-site/examples/data-gl/asset/bathymetry_bw_composite_4k.jpg',
                displacementScale: 0.04,
                shading: 'realistic',
                environment: '#030305',
                realisticMaterial: { roughness: 0.9 },
                postEffect: {
                    enable: true,
                    bloom: { enable: true, bloomIntensity: 0.8 }
                },
                light: {
                    main: { intensity: 1.5, shadow: false },
                    ambientSpecular: { intensity: 0.5 }
                },
                viewControl: { autoRotate: true, autoRotateSpeed: 4, distance: 150 }
            },
            series: [{
                type: 'lines3D',
                coordinateSystem: 'globe',
                blendMode: 'lighter',
                lineStyle: { width: 2, color: '#ef4444', opacity: 0.3 },
                effect: {
                    show: true,
                    trailWidth: 4,
                    trailLength: 0.3,
                    trailOpacity: 1,
                    trailColor: '#ec4899'
                },
                data: dataLines
            }]
        };
    }

    function get2DOption(dataLines) {
        // Map 3D data format down to 2D
        const lines2D = dataLines.map(item => {
            return {
                coords: item.coords,
                lineStyle: { color: colorPalette[Math.floor(Math.random() * colorPalette.length)] }
            }
        });

        // Extract points for scattering effect
        const scatterData = [];
        dataLines.forEach(item => {
            scatterData.push(item.coords[0]); // Source
            scatterData.push(item.coords[1]); // Dest
        });

        return {
            backgroundColor: '#030305',
            geo: {
                map: 'world',
                roam: true,
                zoom: 1.2,
                itemStyle: {
                    areaColor: '#0a0a14',
                    borderColor: 'rgba(99, 102, 241, 0.4)',
                    borderWidth: 1
                },
                emphasis: { itemStyle: { areaColor: '#1a1a2e' } }
            },
            series: [
                {
                    type: 'lines',
                    coordinateSystem: 'geo',
                    zlevel: 2,
                    effect: {
                        show: true,
                        period: 4,
                        trailLength: 0.3,
                        color: '#ec4899',
                        symbolSize: 4
                    },
                    lineStyle: {
                        color: '#ef4444',
                        width: 1,
                        opacity: 0.4,
                        curveness: 0.3
                    },
                    data: lines2D
                },
                {
                    type: 'effectScatter',
                    coordinateSystem: 'geo',
                    zlevel: 2,
                    rippleEffect: { brushType: 'stroke', scale: 4 },
                    itemStyle: { color: '#ef4444' },
                    symbolSize: 6,
                    data: scatterData
                }
            ]
        };
    }

    function setChartMode() {
        myChart.clear();
        if(is3DMode) {
            myChart.setOption(get3DOption(activeLines), true);
        } else {
            myChart.setOption(get2DOption(activeLines), true);
        }
    }

    function updateChartData() {
        if(is3DMode) {
            myChart.setOption({ series: [{ data: activeLines }] });
        } else {
            const opt = get2DOption(activeLines);
            myChart.setOption({ series: opt.series });
        }
    }

    // Toggle Listeners
    btn3d.addEventListener('click', () => { is3DMode = true; btn3d.classList.add('active'); btn2d.classList.remove('active'); setChartMode(); });
    btn2d.addEventListener('click', () => { is3DMode = false; btn2d.classList.add('active'); btn3d.classList.remove('active'); setChartMode(); });

    const btnMinimizeSidebar = document.getElementById('btn-minimize-sidebar');
    if(btnMinimizeSidebar) {
        btnMinimizeSidebar.addEventListener('click', () => {
            const sidebar = document.querySelector('.threat-sidebar');
            sidebar.classList.toggle('minimized');
            const icon = btnMinimizeSidebar.querySelector('i');
            if (sidebar.classList.contains('minimized')) {
                icon.setAttribute('data-lucide', 'chevron-up');
            } else {
                icon.setAttribute('data-lucide', 'chevron-down');
            }
            lucide.createIcons();
        });
    }

    function addToSidebar(threat) {
        const card = document.createElement('div');
        card.className = 'threat-card';
        let imageHtml = '';
        let isNews = threat.threat_type === 'INTELLIGENCE BRIEFING';
        
        if (threat.image) {
            imageHtml = `<img src="${threat.image}" style="width:100%; max-height:220px; object-fit:cover; border-radius: 6px; margin-bottom: 12px; border: 1px solid rgba(255,255,255,0.1);">`;
        }
        
        card.innerHTML = `
            <div class="threat-type" style="color: ${isNews ? '#6366f1' : 'var(--malicious)'};">${threat.threat_type}</div>
            <div class="threat-domain" style="${isNews ? "font-family: 'Outfit'; font-size: 1rem; word-break: normal; font-weight: 600; line-height: 1.4;" : ""}">
                ${threat.source.url}
            </div>
            ${imageHtml}
            <div class="threat-route">
                <span><i data-lucide="crosshair" style="width:12px; height:12px;"></i> ${threat.source.country}</span>
                <span><i data-lucide="arrow-right" style="width:12px; height:12px; color:var(--text-muted)"></i></span>
                <span><i data-lucide="globe" style="width:12px; height:12px; color:${isNews ? '#6366f1' : 'var(--malicious)'}"></i> ${threat.target.country}</span>
            </div>
        `;
        feedContainer.prepend(card);
        // Keep only last 20 items in UI
        if(feedContainer.children.length > 20) {
            feedContainer.removeChild(feedContainer.lastChild);
        }
        lucide.createIcons();
    }

    async function fetchThreats() {
        try {
            const res = await fetch('/api/live-threats');
            const data = await res.json();
            if(data.threats && data.threats.length > 0) {
                liveThreatsPool = data.threats;
            }
        } catch (e) {
            console.error("Failed to fetch live threats");
        }
    }

    function fireRandomThreat() {
        if(liveThreatsPool.length === 0) return;
        
        const threat = liveThreatsPool[Math.floor(Math.random() * liveThreatsPool.length)];
        
        // Add to lines
        const lineData = {
            coords: [
                [parseFloat(threat.source.long), parseFloat(threat.source.lat)], // Source
                [parseFloat(threat.target.long), parseFloat(threat.target.lat)]  // Dest
            ],
            value: 1
        };
        
        activeLines.push(lineData);
        // Keep max 30 lines on screen to prevent lag
        if(activeLines.length > 30) {
            activeLines.shift();
        }
        
        addToSidebar(threat);
        updateChartData();
    }

    // Initialization Flow
    setChartMode();
    
    // Start syncing with backend
    fetchThreats();
    setInterval(fetchThreats, 10000); // Poll backend every 10s for new pool
    
    // Visually fire threats at a readable pace
    setInterval(fireRandomThreat, 4500);

    // Responsive map resize
    window.addEventListener('resize', () => myChart.resize());
});

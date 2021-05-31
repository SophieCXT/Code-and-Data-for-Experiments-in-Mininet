%%%%%%%%%%%%%%%%%%%%%%%%%% Tian: ADAPTIVE STRATEGY EMULATION - MININET DATA %%%%%%%%%%%%%%%%%%%%%%%
cmap = [0, 0.4470, 0.7410;...
    0.8500, 0.3250, 0.0980;...
    0.9290, 0.6940, 0.1250;...
    0.4940, 0.1840, 0.5560;...
    0.4660, 0.6740, 0.1880;...
    0.3010, 0.7450, 0.9330;...
    0.6350, 0.0780, 0.1840];

%%%%%%%%%%%%%%%% LRU, FIFO, Q-LRU, ADAP %%%%%%%%%%%%%%%%%%%
    [fifo, lru, qlru, adap] = hybrid_calculate_hit_ratio();
    [fifo_y, fifo_x] = ecdf(fifo);
    [lru_y, lru_x] = ecdf(lru);
    [qlru_y, qlru_x] = ecdf(qlru);
    [adap_y, adap_x] = ecdf(adap);
    
    
%%%%%%%%%%%%%%% PLOTS %%%%%%%%%%%%%%%%%%%
    %half mice, half elephant attack, lambda_a = 0.001 and then 1.000:
    %%%%%%%%%%%%%%%%%%%
    
    load(['C1000_dos_adaptive_strategy3.mat']);
    s_fifo = Hit_all(1, 1:9);
    s_lru  = Hit_all(2, 1:9);
    s_qlru = Hit_all(3, 1:9);
    s_adap = Hit_all(4, 1:9);
    [f, xfifo] = ecdf(s_fifo);
    [f, xlru]  = ecdf(s_lru);
    [f, xqlru] = ecdf(s_qlru);
    [f, xadap] = ecdf(s_adap);
    
    figure;
    plot(fifo_x,fifo_y, 'LineWidth', 2, 'Color', cmap(1,:));
    hold on;
    set(gca,'XTick',(0:0.1:1))
    plot(lru_x,lru_y, 'LineWidth', 2, 'Color', cmap(5,:));
    plot(qlru_x,qlru_y, 'LineWidth', 2, 'Color', cmap(3,:));
    plot(adap_x,adap_y, 'LineWidth', 2, 'Color', 'r');
    % simulation as dashed, emulation as solid
    plot(xfifo,f, 'LineWidth', 1.5, 'LineStyle','--', 'Color', cmap(1,:));
    plot(xlru,f, 'LineWidth', 1.5, 'LineStyle','--', 'Color', cmap(5,:));
    plot(xqlru,f, 'LineWidth', 1.5, 'LineStyle','--', 'Color', cmap(3,:));
    plot(xadap,f, 'LineWidth', 1.5, 'LineStyle','--', 'Color', 'r');
    %title('Hybrid DoS attack: \Lambda_a = 1000 | \lambda_a = [0.001, 1] half mice half elephant')
    legend('FIFO','LRU', 'q-LRU', 'Adaptive');
    ylabel('CDF');
    xlabel('avg hit ratio');
    hold off;
    
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    function [ x,f ] = empirical_cdf( data )
        % f(x) is the staircase empirical CDF based on 'data'
        x = sort(data);
        f = ([1:length(data)]./length(data));
    end
%%%%%%%%%%%%%%%%%%%%%%%%%% EMULATION - MININET DATA %%%%%%%%%%%%%%%%%%%%%%%
cmap = [0, 0.4470, 0.7410;...
    0.8500, 0.3250, 0.0980;...
    0.9290, 0.6940, 0.1250;...
    0.4940, 0.1840, 0.5560;...
    0.4660, 0.6740, 0.1880;...
    0.3010, 0.7450, 0.9330;...
    0.6350, 0.0780, 0.1840];
%%%%%%%%%%%%%%%% LRU %%%%%%%%%%%%%%%%%%%
    %[elephant, mice] = calculate_hit_ratio(strategy)
    [lru1, lru3] = calculate_hit_ratio("LRU"); 
    [lru_y1, lru_x1] = ecdf(lru1);
    [lru_y3, lru_x3] = ecdf(lru3);
    
%%%%%%%%%%%%%%%% FIFO %%%%%%%%%%%%%%%%%%%
    [fifo1, fifo3] = calculate_hit_ratio("FIFO");
    [fifo_y1, fifo_x1] = ecdf(fifo1);
    [fifo_y3, fifo_x3] = ecdf(fifo3);
    
%%%%%%%%%%%%%%%% Q-LRU %%%%%%%%%%%%%%%%%%%
    [qlru1, qlru3] = calculate_hit_ratio("Q-LRU");
    [qlru_y1, qlru_x1] = ecdf(qlru1);
    [qlru_y3, qlru_x3] = ecdf(qlru3);
    
    
%%%%%%%%%%%%%%% SIMULATION %%%%%%%%%%%%%%%
    load(['logs/constant_strategy2.mat']);
    s_fifo = Hit_s(1, 1:9);
    s_lru  = Hit_s(2, 1:9);
    s_qlru = Hit_s(3, 1:9);
    [f, xfifo_1] = ecdf(s_fifo);
    [f, xlru_1]  = ecdf(s_lru);
    [f, xqlru_1] = ecdf(s_qlru);

%%%%%%%%%%%%%%% PLOTS %%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    %lambda_a = 1:
    %%%%%%%%%%%%%%%
    figure;
    plot(fifo_x1,fifo_y1, 'Color', cmap(1,:),'LineWidth', 2);
    hold on;
    set(gca,'XTick',(0:0.1:1))
    plot(lru_x1,lru_y1, 'Color', cmap(5,:),'LineWidth', 2);
    plot(qlru_x1,qlru_y1, 'Color', cmap(3,:),'LineWidth', 2);
    plot(xfifo_1,f, 'Color', cmap(1,:), 'LineWidth', 1.5, 'LineStyle','--');
    plot(xlru_1,f, 'Color', cmap(5,:),'LineWidth', 1.5, 'LineStyle','--');
    plot(xqlru_1,f, 'Color', cmap(3,:),'LineWidth', 1.5, 'LineStyle','--');
    legend('FIFO','LRU', 'q-LRU');
%     title('DoS attack on traces under total attack rate 1000 | \lambda_a = 1')
    ylabel('CDF');
    xlabel('avg hit ratio');
    hold off;

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    %lambda_a = 0.001:
    %%%%%%%%%%%%%%%%%%%
    
    load(['logs/constant_strategy1.mat']);
    s_fifo = Hit_s(1, 1:9);
    s_lru  = Hit_s(2, 1:9);
    s_qlru = Hit_s(3, 1:9);
    [f, xfifo_3] = ecdf(s_fifo);
    [f, xlru_3]  = ecdf(s_lru);
    [f, xqlru_3] = ecdf(s_qlru);
    
    figure;
    plot(fifo_x3,fifo_y3, 'LineWidth', 2, 'Color', cmap(1,:));
    hold on;
    set(gca,'XTick',(0:0.1:1))
    plot(lru_x3,lru_y3, 'LineWidth', 2, 'Color', cmap(5,:));
    plot(qlru_x3,qlru_y3, 'LineWidth', 2, 'Color', cmap(3,:));
    plot(xfifo_3,f, 'LineWidth', 1.5, 'LineStyle','--', 'Color', cmap(1,:));
    plot(xlru_3,f, 'LineWidth', 1.5, 'LineStyle','--', 'Color', cmap(5,:));
    plot(xqlru_3,f, 'LineWidth', 1.5, 'LineStyle','--', 'Color', cmap(3,:));
    %title('DoS attack on traces under total attack rate 1000 | \lambda_a = 0.001')
    legend('FIFO','LRU', 'q-LRU');
    ylabel('CDF');
    xlabel('avg hit ratio');
    hold off;
    
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    function [ x,f ] = empirical_cdf( data )
        % f(x) is the staircase empirical CDF based on 'data'
        x = sort(data);
        f = ([1:length(data)]./length(data));
    end
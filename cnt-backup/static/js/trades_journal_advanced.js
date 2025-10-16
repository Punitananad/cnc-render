// Advanced Trading Journal Features
class TradingJournalAdvanced {
    constructor() {
        this.table = null;
        this.autoRefreshInterval = null;
        this.init();
    }

    init() {
        this.initDataTable();
        this.bindEvents();
        this.checkBrokerStatus();
        this.loadAdvancedAnalytics();
        setTimeout(() => {
            this.initBulkOperations();
        }, 1000);
    }

    initDataTable() {
        this.table = $('#trades-table').DataTable({
            pageLength: 25,
            order: [[0, 'desc']],
            responsive: true,
            stateSave: true,
            dom: '<"row"<"col-sm-12 col-md-6"l><"col-sm-12 col-md-6"f>>rtip',
            columnDefs: [
                { targets: [6], className: 'text-end' },
                { targets: [9], orderable: false }
            ],
            language: {
                search: "Search:",
                lengthMenu: "Show _MENU_ entries",
                info: "Showing _START_ to _END_ of _TOTAL_ entries",
                paginate: {
                    first: "First",
                    last: "Last",
                    next: "Next",
                    previous: "Previous"
                }
            }
        });
    }

    bindEvents() {
        // Broker connections
        $(document).on('click', '.btn-outline-success[data-broker]', (e) => {
            const broker = $(e.target).data('broker');
            this.connectToBroker(broker, $(e.target));
        });

        // Import trades
        $(document).on('click', '.btn-outline-primary[data-broker]', (e) => {
            const broker = $(e.target).data('broker');
            if ($(e.target).prop('disabled')) {
                this.showNotification('Please connect to the broker first', 'warning');
                return;
            }
            this.showImportOptions(broker);
        });

        // Execute import
        $('#execute-import').on('click', () => {
            this.executeImport();
        });

        // Trade actions
        $(document).on('click', '.delete-trade', (e) => {
            e.preventDefault();
            const tradeId = $(e.target).closest('button').data('id');
            this.deleteTrade(tradeId, $(e.target).closest('button'));
        });

        $(document).on('click', '.view-trade', (e) => {
            e.preventDefault();
            const tradeId = $(e.target).closest('button').data('id');
            this.viewTradeDetails(tradeId, $(e.target).closest('button'));
        });

        $(document).on('click', '.duplicate-trade', (e) => {
            e.preventDefault();
            const tradeId = $(e.target).closest('button').data('id');
            this.duplicateTrade(tradeId);
        });

        // Filters
        $('#apply-filters').on('click', () => this.applyFilters());
        $('#reset-filters').on('click', () => this.resetFilters());

        // Export
        $('#export-csv').on('click', () => this.exportToCSV());
        $('#export-excel').on('click', () => this.exportToExcel());
        $('#export-pdf').on('click', () => this.exportToPDF());

        // Analytics
        $('#refresh-analytics').on('click', () => this.loadAdvancedAnalytics());

        // Auto refresh
        $('#auto-refresh').on('change', (e) => {
            if ($(e.target).is(':checked')) {
                this.startAutoRefresh();
            } else {
                this.stopAutoRefresh();
            }
        });
    }

    connectToBroker(broker, $btn) {
        $btn.prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> Connecting...');
        
        setTimeout(() => {
            window.location.href = `/calculatentrade_journal/connect_broker?broker=${broker}`;
        }, 1000);
    }

    showImportOptions(broker) {
        $('#broker-import-options').show();
        $('#execute-import').data('broker', broker);
    }

    executeImport() {
        const broker = $('#execute-import').data('broker');
        const fromDate = $('#import-from-date').val();
        const toDate = $('#import-to-date').val();
        const strategyId = $('#import-strategy').val();
        const skipDuplicates = $('#skip-duplicates').is(':checked');
        const autoCategorize = $('#auto-categorize').is(':checked');
        
        if (!fromDate || !toDate) {
            this.showNotification('Please select a date range', 'warning');
            return;
        }
        
        this.importTradesFromBroker(broker, fromDate, toDate, strategyId, {
            skipDuplicates,
            autoCategorize
        });
    }

    importTradesFromBroker(broker, fromDate, toDate, strategyId, options) {
        $('#importProgressModal').modal('show');
        $('#import-progress-bar').css('width', '10%');
        $('#import-status').text('Fetching trades from broker...');

        $.get(`/calculatentrade_journal/api/broker/trades?broker=${broker}&user_id=default&from=${fromDate}&to=${toDate}`)
            .done((response) => {
                if (response.ok && response.data) {
                    this.processImportedTrades(response.data, broker, strategyId, options);
                } else {
                    this.showImportError('Failed to fetch trades from broker');
                }
            })
            .fail(() => {
                this.showImportError('Error connecting to broker');
            });
    }

    processImportedTrades(trades, broker, strategyId, options) {
        $('#import-progress-bar').css('width', '50%');
        $('#import-status').text('Processing trades...');
        
        let importedCount = 0;
        const totalCount = trades.length;
        
        if (totalCount === 0) {
            $('#import-progress-bar').css('width', '100%');
            $('#import-status').text('No trades found in the selected date range');
            setTimeout(() => $('#importProgressModal').modal('hide'), 2000);
            return;
        }
        
        trades.forEach((trade, index) => {
            const formattedTrade = this.formatTradeForImport(trade, broker, strategyId);
            
            $.ajax({
                url: '/calculatentrade_journal/api/trades/from_broker',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify(formattedTrade)
            }).always(() => {
                importedCount++;
                const progress = 50 + (importedCount / totalCount) * 50;
                $('#import-progress-bar').css('width', `${progress}%`);
                $('#import-status').text(`Imported ${importedCount} of ${totalCount} trades`);
                
                if (importedCount === totalCount) {
                    setTimeout(() => {
                        $('#importProgressModal').modal('hide');
                        this.showNotification(`Successfully imported ${totalCount} trades`, 'success');
                        location.reload();
                    }, 1000);
                }
            });
        });
    }

    formatTradeForImport(trade, broker, strategyId) {
        let formatted = { strategy_id: strategyId || null };
        
        switch(broker) {
            case 'kite':
                formatted.symbol = trade.tradingsymbol;
                formatted.entry_price = trade.average_price || trade.price;
                formatted.exit_price = trade.average_price || trade.price;
                formatted.quantity = Math.abs(trade.quantity);
                formatted.trade_type = trade.transaction_type === 'BUY' ? 'long' : 'short';
                formatted.date = trade.order_timestamp ? trade.order_timestamp.split('T')[0] : new Date().toISOString().split('T')[0];
                break;
            case 'dhan':
                formatted.symbol = trade.symbol;
                formatted.entry_price = trade.averagePrice || trade.tradePrice;
                formatted.exit_price = trade.averagePrice || trade.tradePrice;
                formatted.quantity = Math.abs(trade.quantity);
                formatted.trade_type = trade.transactionType === 'BUY' ? 'long' : 'short';
                formatted.date = trade.tradeDate || new Date().toISOString().split('T')[0];
                break;
            case 'angel':
                formatted.symbol = trade.tradingsymbol;
                formatted.entry_price = trade.averageprice || trade.price;
                formatted.exit_price = trade.averageprice || trade.price;
                formatted.quantity = Math.abs(trade.quantity);
                formatted.trade_type = trade.transactiontype === 'BUY' ? 'long' : 'short';
                formatted.date = trade.orderdatetime ? trade.orderdatetime.split(' ')[0] : new Date().toISOString().split('T')[0];
                break;
        }
        
        return formatted;
    }

    showImportError(message) {
        $('#import-status').text(message);
        setTimeout(() => $('#importProgressModal').modal('hide'), 2000);
    }

    deleteTrade(tradeId, $btn) {
        if (!confirm('Are you sure you want to delete this trade? This action cannot be undone.')) {
            return;
        }

        $btn.prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i>');
        
        $.ajax({
            url: `/calculatentrade_journal/api/trades/${tradeId}`,
            method: 'DELETE',
            timeout: 10000
        }).done((response) => {
            if (response && response.success) {
                const row = $btn.closest('tr');
                this.table.row(row).remove().draw();
                this.showNotification('Trade deleted successfully', 'success');
                this.updateStats();
            } else {
                this.showNotification('Failed to delete trade: ' + (response.message || 'Unknown error'), 'error');
                $btn.prop('disabled', false).html('<i class="fas fa-trash"></i>');
            }
        }).fail((xhr, status) => {
            let errorMsg = 'Error deleting trade';
            if (status === 'timeout') {
                errorMsg = 'Request timed out. Please try again.';
            } else if (xhr.responseJSON && xhr.responseJSON.message) {
                errorMsg = xhr.responseJSON.message;
            }
            this.showNotification(errorMsg, 'error');
            $btn.prop('disabled', false).html('<i class="fas fa-trash"></i>');
        });
    }

    viewTradeDetails(tradeId, $btn) {
        $btn.prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i>');
        
        $.ajax({
            url: `/calculatentrade_journal/api/trades/${tradeId}`,
            method: 'GET',
            timeout: 10000
        }).done((trade) => {
            this.displayTradeDetails(trade);
            $btn.prop('disabled', false).html('<i class="fas fa-eye"></i>');
        }).fail((xhr, status) => {
            let errorMsg = 'Error loading trade details';
            if (status === 'timeout') {
                errorMsg = 'Request timed out. Please try again.';
            }
            this.showNotification(errorMsg, 'error');
            $btn.prop('disabled', false).html('<i class="fas fa-eye"></i>');
        });
    }

    displayTradeDetails(trade) {
        let detailsHtml = `
            <div class="row">
                <div class="col-md-6">
                    <h6>Trade Information</h6>
                    <table class="table table-sm">
                        <tr><td><strong>Symbol:</strong></td><td>${trade.symbol}</td></tr>
                        <tr><td><strong>Date:</strong></td><td>${trade.date}</td></tr>
                        <tr><td><strong>Type:</strong></td><td>${trade.trade_type === 'long' ? 'Long' : 'Short'}</td></tr>
                        <tr><td><strong>Quantity:</strong></td><td>${trade.quantity}</td></tr>
                    </table>
                </div>
                <div class="col-md-6">
                    <h6>Price Information</h6>
                    <table class="table table-sm">
                        <tr><td><strong>Entry Price:</strong></td><td>${trade.entry_price.toFixed(2)}</td></tr>
                        <tr><td><strong>Exit Price:</strong></td><td>${trade.exit_price.toFixed(2)}</td></tr>
                        <tr><td><strong>P&L:</strong></td><td class="${trade.pnl > 0 ? 'profit' : trade.pnl < 0 ? 'loss' : ''}">${trade.pnl.toFixed(2)}</td></tr>
                        <tr><td><strong>Result:</strong></td><td>
                            <span class="badge ${trade.result === 'win' ? 'win-badge' : trade.result === 'loss' ? 'loss-badge' : 'breakeven-badge'}">
                                ${trade.result}
                            </span>
                        </td></tr>
                    </table>
                </div>
            </div>
        `;
        
        if (trade.notes) {
            detailsHtml += `
                <div class="row mt-3">
                    <div class="col-12">
                        <h6>Notes</h6>
                        <p>${trade.notes}</p>
                    </div>
                </div>
            `;
        }
        
        if (trade.strategy) {
            detailsHtml += `
                <div class="row mt-3">
                    <div class="col-12">
                        <h6>Strategy</h6>
                        <p><span class="badge bg-info">${trade.strategy.name}</span></p>
                    </div>
                </div>
            `;
        }
        
        $('#trade-details-content').html(detailsHtml);
        $('#tradeDetailsModal').modal('show');
    }

    duplicateTrade(tradeId) {
        $.get(`/calculatentrade_journal/api/trades/${tradeId}`)
            .done((trade) => {
                const params = new URLSearchParams({
                    symbol: trade.symbol,
                    trade_type: trade.trade_type,
                    entry_price: trade.entry_price,
                    quantity: trade.quantity,
                    strategy_id: trade.strategy_id || ''
                });
                window.location.href = `/calculatentrade_journal/trade_form?${params.toString()}`;
            })
            .fail(() => {
                this.showNotification('Error loading trade data for duplication', 'error');
            });
    }

    applyFilters() {
        const filters = {
            result: $('#filter-result').val(),
            strategy: $('#filter-strategy').val(),
            type: $('#filter-type').val(),
            dateFrom: $('#filter-date-from').val(),
            dateTo: $('#filter-date-to').val(),
            search: $('#search-trades').val(),
            pnlMin: $('#pnl-min').val(),
            pnlMax: $('#pnl-max').val(),
            qtyMin: $('#qty-min').val(),
            qtyMax: $('#qty-max').val(),
            sortBy: $('#sort-by').val()
        };

        let url = '/calculatentrade_journal/api/trades?';
        const params = [];
        
        Object.keys(filters).forEach(key => {
            if (filters[key] && filters[key] !== 'all') {
                params.push(`${key}=${encodeURIComponent(filters[key])}`);
            }
        });
        
        url += params.join('&');
        
        $.get(url)
            .done((response) => {
                this.updateTableData(response.trades);
            })
            .fail(() => {
                this.showNotification('Error applying filters', 'error');
            });
    }

    resetFilters() {
        $('#filter-result, #filter-strategy, #filter-type, #sort-by').val('all');
        $('#filter-date-from, #filter-date-to, #search-trades, #pnl-min, #pnl-max, #qty-min, #qty-max').val('');
        this.applyFilters();
    }

    updateTableData(trades) {
        this.table.clear();
        trades.forEach(trade => {
            this.table.row.add([
                trade.date,
                trade.symbol,
                `<span class="badge ${trade.trade_type === 'long' ? 'bg-success' : 'bg-danger'}">${trade.trade_type === 'long' ? 'Long' : 'Short'}</span>`,
                trade.entry_price.toFixed(2),
                trade.exit_price.toFixed(2),
                trade.quantity,
                `<span class="${trade.pnl > 0 ? 'profit' : trade.pnl < 0 ? 'loss' : ''}">${trade.pnl.toFixed(2)}</span>`,
                `<span class="badge ${trade.result === 'win' ? 'win-badge' : trade.result === 'loss' ? 'loss-badge' : 'breakeven-badge'}">${trade.result}</span>`,
                trade.strategy ? `<span class="badge bg-info">${trade.strategy.name}</span>` : '<span class="text-muted">-</span>',
                this.generateActionButtons(trade.id)
            ]);
        });
        this.table.draw();
    }

    generateActionButtons(tradeId) {
        return `
            <div class="btn-group" role="group">
                <a href="/calculatentrade_journal/trade_form/${tradeId}" class="btn btn-sm btn-outline-primary" title="Edit">
                    <i class="fas fa-edit"></i>
                </a>
                <button class="btn btn-sm btn-outline-danger delete-trade" data-id="${tradeId}" title="Delete">
                    <i class="fas fa-trash"></i>
                </button>
                <button class="btn btn-sm btn-outline-info view-trade" data-id="${tradeId}" title="View Details">
                    <i class="fas fa-eye"></i>
                </button>
                <button class="btn btn-sm btn-outline-secondary duplicate-trade" data-id="${tradeId}" title="Duplicate Trade">
                    <i class="fas fa-copy"></i>
                </button>
            </div>
        `;
    }

    exportToCSV() {
        const data = this.table.rows().data().toArray();
        let csvContent = "Date,Symbol,Type,Entry Price,Exit Price,Quantity,P&L,Result,Strategy\n";
        
        data.forEach(row => {
            const cleanRow = row.map(cell => {
                if (typeof cell === 'string') {
                    return cell.replace(/<[^>]*>/g, '').replace(/"/g, '""');
                }
                return cell;
            });
            csvContent += `"${cleanRow.join('","')}"\n`;
        });
        
        this.downloadFile(csvContent, 'text/csv', `trades_${new Date().toISOString().split('T')[0]}.csv`);
    }

    exportToExcel() {
        this.showNotification('Excel export feature coming soon', 'info');
    }

    exportToPDF() {
        this.showNotification('PDF export feature coming soon', 'info');
    }

    downloadFile(content, type, filename) {
        const blob = new Blob([content], { type: type });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.setAttribute('hidden', '');
        a.setAttribute('href', url);
        a.setAttribute('download', filename);
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }

    checkBrokerStatus() {
        const brokers = ['kite', 'dhan', 'angel'];
        brokers.forEach(broker => {
            $.get(`/calculatentrade_journal/api/broker/status?broker=${broker}&user_id=default`)
                .done((response) => {
                    if (response.connected) {
                        $(`#${broker}-status`).html(`
                            <i class="fas fa-circle broker-connected"></i>
                            <span>Connected</span>
                        `);
                        $(`#import-${broker}-trades`).prop('disabled', false);
                    }
                })
                .fail(() => {
                    $(`#${broker}-status`).html(`
                        <i class="fas fa-circle broker-disconnected"></i>
                        <span>Not Connected</span>
                    `);
                    $(`#import-${broker}-trades`).prop('disabled', true);
                });
        });
    }

    loadAdvancedAnalytics() {
        $.get('/calculatentrade_journal/api/analytics')
            .done((data) => {
                $('#avg-win').text(data.avg_win ? data.avg_win.toFixed(2) : '0.00');
                $('#avg-loss').text(data.avg_loss ? Math.abs(data.avg_loss).toFixed(2) : '0.00');
                $('#profit-factor').text(data.profit_factor ? data.profit_factor.toFixed(2) : '0.00');
                $('#max-drawdown').text(data.max_drawdown ? data.max_drawdown.toFixed(2) : '0.00');
                $('#sharpe-ratio').text(data.sharpe_ratio ? data.sharpe_ratio.toFixed(2) : '0.00');
                $('#total-volume').text(data.total_volume ? data.total_volume.toLocaleString() : '0');
                $('#best-symbol').text(data.best_symbol || '-');
                $('#most-traded').text(data.most_traded || '-');
            })
            .fail(() => {
                console.log('Failed to load analytics');
            });
    }

    updateStats() {
        $.get('/calculatentrade_journal/api/stats')
            .done((stats) => {
                $('.stats-value').eq(0).text(stats.total_pnl ? stats.total_pnl.toFixed(2) : '0.00');
                $('.stats-value').eq(1).text(stats.total_trades || '0');
                $('.stats-value').eq(2).text(stats.win_rate ? stats.win_rate.toFixed(1) + '%' : '0%');
                $('.stats-value').eq(3).text((stats.winning_trades || '0') + '/' + (stats.losing_trades || '0'));
            })
            .fail(() => {
                console.log('Failed to update stats');
            });
    }

    initBulkOperations() {
        // Add bulk select checkboxes
        $('#trades-table thead tr').prepend('<th><input type="checkbox" id="select-all"></th>');
        $('#trades-table tbody tr').each(function() {
            const tradeId = $(this).find('.delete-trade').data('id');
            $(this).prepend(`<td><input type="checkbox" class="trade-select" data-id="${tradeId}"></td>`);
        });
        
        // Add bulk action buttons
        const bulkActions = $(`
            <div class="bulk-actions mt-2" style="display: none;">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <span class="badge bg-primary" id="selected-count">0 selected</span>
                    </div>
                    <div>
                        <button class="btn btn-sm btn-danger" id="bulk-delete">
                            <i class="fas fa-trash me-1"></i>Delete Selected
                        </button>
                        <button class="btn btn-sm btn-info" id="bulk-export">
                            <i class="fas fa-download me-1"></i>Export Selected
                        </button>
                        <button class="btn btn-sm btn-warning" id="bulk-assign-strategy">
                            <i class="fas fa-tag me-1"></i>Assign Strategy
                        </button>
                    </div>
                </div>
            </div>
        `);
        
        $('.card-body').first().prepend(bulkActions);
        
        this.bindBulkEvents();
    }

    bindBulkEvents() {
        // Select all functionality
        $('#select-all').on('change', function() {
            $('.trade-select').prop('checked', $(this).prop('checked'));
            $(this).trigger('bulk-selection-changed');
        });
        
        // Individual selection
        $(document).on('change', '.trade-select', function() {
            const selectedCount = $('.trade-select:checked').length;
            $('#selected-count').text(`${selectedCount} selected`);
            
            if (selectedCount > 0) {
                $('.bulk-actions').show();
            } else {
                $('.bulk-actions').hide();
            }
        });
        
        // Bulk delete
        $('#bulk-delete').on('click', () => {
            const selectedIds = $('.trade-select:checked').map(function() {
                return $(this).data('id');
            }).get();
            
            if (selectedIds.length === 0) {
                this.showNotification('No trades selected', 'warning');
                return;
            }
            
            if (confirm(`Are you sure you want to delete ${selectedIds.length} selected trades?`)) {
                this.bulkDeleteTrades(selectedIds);
            }
        });
        
        // Bulk assign strategy
        $('#bulk-assign-strategy').on('click', () => {
            const selectedIds = $('.trade-select:checked').map(function() {
                return $(this).data('id');
            }).get();
            
            if (selectedIds.length === 0) {
                this.showNotification('No trades selected', 'warning');
                return;
            }
            
            this.showStrategySelectionModal(selectedIds);
        });
    }

    bulkDeleteTrades(tradeIds) {
        const promises = tradeIds.map(id => {
            return $.ajax({
                url: `/calculatentrade_journal/api/trades/${id}`,
                method: 'DELETE'
            });
        });
        
        Promise.allSettled(promises).then(results => {
            const successful = results.filter(r => r.status === 'fulfilled').length;
            const failed = results.length - successful;
            
            if (successful > 0) {
                this.showNotification(`Successfully deleted ${successful} trades`, 'success');
                location.reload();
            }
            
            if (failed > 0) {
                this.showNotification(`Failed to delete ${failed} trades`, 'error');
            }
        });
    }

    showStrategySelectionModal(tradeIds) {
        // This would need to be implemented with actual strategy data
        this.showNotification('Strategy assignment feature coming soon', 'info');
    }

    startAutoRefresh() {
        this.autoRefreshInterval = setInterval(() => {
            this.checkBrokerStatus();
            if ($('#auto-refresh').is(':checked')) {
                this.applyFilters();
            }
        }, 30000);
    }
    
    stopAutoRefresh() {
        if (this.autoRefreshInterval) {
            clearInterval(this.autoRefreshInterval);
        }
    }

    showNotification(message, type = 'info', duration = 5000) {
        const alertClass = {
            'success': 'alert-success',
            'error': 'alert-danger',
            'warning': 'alert-warning',
            'info': 'alert-info'
        }[type] || 'alert-info';
        
        const notification = $(`
            <div class="alert ${alertClass} alert-dismissible fade show position-fixed" 
                 style="top: 20px; right: 20px; z-index: 9999; min-width: 300px;">
                <strong>${type.charAt(0).toUpperCase() + type.slice(1)}:</strong> ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `);
        
        $('body').append(notification);
        
        if (duration > 0) {
            setTimeout(() => {
                notification.alert('close');
            }, duration);
        }
    }
}

// Initialize when document is ready
$(document).ready(function() {
    new TradingJournalAdvanced();
});